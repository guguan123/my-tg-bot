#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <curl/curl.h>
#include <cjson/cJSON.h>
#include <sqlite3.h>
#include <signal.h>

#ifdef _WIN32
#include <windows.h>
#else
#include <unistd.h>
#endif

#define API_BASE "https://api.telegram.org/bot"
#define DB_FILE "tg_bot.db"
#define POLL_INTERVAL 1       // 默认轮询间隔（秒）
#define MY_USER_ID 6524442943

// 内存结构，用于 CURL 回调收集响应
typedef struct {
	char *memory;
	size_t size;
} MemoryStruct;

// 全局标志，用于退出循环
volatile sig_atomic_t keep_running = 1;

// 信号处理函数
static void signal_handler(int sig) {
	(void)sig;  // 防止编译器警告
	keep_running = 0;
	fprintf(stderr, "[INFO] Received signal, shutting down gracefully...\n");
}

// CURL 写回调函数：收集 HTTP 响应数据
static size_t write_callback(void *contents, size_t size, size_t nmemb, void *userp) {
	size_t realsize = size * nmemb;
	MemoryStruct *mem = (MemoryStruct *)userp;
	char *ptr = realloc(mem->memory, mem->size + realsize + 1);
	if (ptr == NULL) {
		// 内存分配失败
		fprintf(stderr, "[ERROR] realloc failed in write_callback\n");
		return 0;
	}
	mem->memory = ptr;
	memcpy(&(mem->memory[mem->size]), contents, realsize);
	mem->size += realsize;
	mem->memory[mem->size] = 0;
	return realsize;
}

// 初始化 CURL 并设置通用选项，包括 CA 证书
CURL *init_curl_with_options() {
	CURL *curl = curl_easy_init();
	if (!curl) {
		fprintf(stderr, "[ERROR] Failed to init CURL\n");
		return NULL;
	}

	// 从环境变量 CURL_CA_BUNDLE 读取路径
	const char *ca_path = getenv("CURL_CA_BUNDLE");
	if (ca_path) {
		curl_easy_setopt(curl, CURLOPT_CAINFO, ca_path);
		fprintf(stderr, "[INFO] Using CA bundle from env: %s\n", ca_path);
	} else {
#ifdef _WIN32
		fprintf(stderr, "[WARNING] No CURL_CA_BUNDLE set, using default CA or may have SSL issues.\n");
#endif
		// 可选：禁用SSL验证
		//curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
		//curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
	}

	return curl;
}

// 发送消息函数：使用 CURL 发送 Telegram 消息，并记录到数据库
void send_message(long long chat_id, const char *text, sqlite3 *db, const char *token) {
	CURL *curl = init_curl_with_options();
	if (!curl) return;

	// 构建 API URL
	char url[512];
	snprintf(url, sizeof(url), "%s%s/sendMessage", API_BASE, token);
	fprintf(stderr, "[INFO] Sending message to chat_id %lld: %s\n", chat_id, text);

	// 构建 POST fields
	curl_mime *mime = curl_mime_init(curl);
    curl_mimepart *part;

    // 添加 chat_id
    part = curl_mime_addpart(mime);
    curl_mime_name(part, "chat_id");
    char chat_id_str[32];
    snprintf(chat_id_str, sizeof(chat_id_str), "%lld", chat_id);
    curl_mime_data(part, chat_id_str, CURL_ZERO_TERMINATED);

    // 添加 text
    part = curl_mime_addpart(mime);
    curl_mime_name(part, "text");
    curl_mime_data(part, text, CURL_ZERO_TERMINATED);

    curl_easy_setopt(curl, CURLOPT_MIMEPOST, mime);
	curl_easy_setopt(curl, CURLOPT_URL, url);

	// 执行请求
	CURLcode res = curl_easy_perform(curl);
	if (res == CURLE_OK) {
		// 检查 HTTP 状态码
		long http_code = 0;
		curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
		if (http_code == 200) {
			fprintf(stderr, "[INFO] Message sent successfully to chat_id %lld\n", chat_id);
		} else {
			fprintf(stderr, "[ERROR] Telegram API returned HTTP %ld in send_message\n", http_code);
		}
	} else {
		fprintf(stderr, "[ERROR] CURL perform failed in send_message: %s\n", curl_easy_strerror(res));
	}
    curl_mime_free(mime);
	curl_easy_cleanup(curl);

	// 存到数据库，使用 prepared statement 防 SQL 注入
	sqlite3_stmt *stmt;
	const char *sql = "INSERT INTO messages (chat_id, text, is_bot) VALUES (?, ?, 1);";
	if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) {
		fprintf(stderr, "[ERROR] Failed to prepare SQL in send_message: %s\n", sqlite3_errmsg(db));
		return;
	}
	sqlite3_bind_int64(stmt, 1, chat_id);
	sqlite3_bind_text(stmt, 2, text, -1, SQLITE_STATIC);
	if (sqlite3_step(stmt) == SQLITE_DONE) {
		fprintf(stderr, "[INFO] Message logged to DB for chat_id %lld\n", chat_id);
	} else {
		fprintf(stderr, "[ERROR] Failed to execute SQL in send_message: %s\n", sqlite3_errmsg(db));
	}
	sqlite3_finalize(stmt);
}

// 处理更新函数：解析 Telegram 更新，处理消息并响应
void process_update(cJSON *update, sqlite3 *db, const char *token) {
	if (!update) return;

	cJSON *message = cJSON_GetObjectItem(update, "message");
	if (!message) {
		fprintf(stderr, "[INFO] Update without message, skipping\n");
		return;
	}

	// 获取 chat_id
	cJSON *chat = cJSON_GetObjectItem(message, "chat");
	if (!chat) return;
	cJSON *chat_id_item = cJSON_GetObjectItem(chat, "id");
	if (!chat_id_item || !cJSON_IsNumber(chat_id_item)) {
		fprintf(stderr, "[ERROR] Invalid chat_id in update\n");
		return;
	}
	long long chat_id = (long long)chat_id_item->valuedouble;

	// 获取 from 和 user_id
	cJSON *from = cJSON_GetObjectItem(message, "from");
	if (!from) return;
	cJSON *user_id_item = cJSON_GetObjectItem(from, "id");
	if (!user_id_item || !cJSON_IsNumber(user_id_item)) {
		fprintf(stderr, "[ERROR] Invalid user_id in update\n");
		return;
	}
	long long user_id = (long long)user_id_item->valuedouble;

	// 获取 username 和 text
	cJSON *username_item = cJSON_GetObjectItem(from, "username");
	const char *username = username_item ? username_item->valuestring : "N/A";
	cJSON *text_item = cJSON_GetObjectItem(message, "text");
	if (!text_item || !cJSON_IsString(text_item)) {
		fprintf(stderr, "[INFO] Message without text, skipping\n");
		return;
	}
	const char *text = text_item->valuestring;
	fprintf(stderr, "[INFO] Received message from user %lld (@%s): %s\n", user_id, username, text);

	// 存收到消息到数据库
	sqlite3_stmt *stmt;
	const char *sql = "INSERT INTO messages (chat_id, text, is_bot) VALUES (?, ?, 0);";
	if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) {
		fprintf(stderr, "[ERROR] Failed to prepare SQL for received message: %s\n", sqlite3_errmsg(db));
		return;
	}
	sqlite3_bind_int64(stmt, 1, chat_id);
	sqlite3_bind_text(stmt, 2, text, -1, SQLITE_STATIC);
	if (sqlite3_step(stmt) != SQLITE_DONE) {
		fprintf(stderr, "[ERROR] Failed to insert received message: %s\n", sqlite3_errmsg(db));
	} else {
		fprintf(stderr, "[INFO] Received message logged to DB\n");
	}
	sqlite3_finalize(stmt);

	// 处理命令
	if (strncmp(text, "/start", 6) == 0) {
		send_message(chat_id, "Hello world", db, token);
	} else if (strncmp(text, "/info", 5) == 0) {
		char info[256];
		snprintf(info, sizeof(info), "Your ID: %lld\nYour Username: %s", user_id, username);
		send_message(chat_id, info, db, token);
	} else if (strncmp(text, "/cmd ", 5) == 0) {
		// 仅管理员可用
		if (user_id != MY_USER_ID) {
			fprintf(stderr, "[WARN] Unauthorized access attempt from user %lld\n", user_id);
			send_message(chat_id, "Sorry, this command is for owner only.", db, token);  // 可选回复
			return;
		}

		const char *cmd = NULL;
		cmd = text + 5;

		// 简单过滤一些危险命令（但是不启用）
		if (0 || strstr(cmd, "rm -rf /") || strstr(cmd, ":(){ :|:& };:") || strstr(cmd, "mkfs")) {
			send_message(chat_id, "Meow~ That's too dangerous, master~", db, token);
			return;
		}

		fprintf(stderr, "[INFO] Executing command for owner: %s\n", cmd);

		// 执行命令并捕获输出
		char *output = NULL;
		size_t output_size = 0;
		FILE *fp = popen(cmd, "r");
		if (fp == NULL) {
			send_message(chat_id, "popen failed :(", db, token);
			return;
		}

		char buffer[1024];
		while (fgets(buffer, sizeof(buffer), fp) != NULL) {
			size_t len = strlen(buffer);
			char *new_output = realloc(output, output_size + len + 1);
			if (new_output == NULL) {
				free(output);
				pclose(fp);
				send_message(chat_id, "Memory allocation failed", db, token);
				return;
			}
			output = new_output;
			memcpy(output + output_size, buffer, len);
			output_size += len;
			output[output_size] = '\0';
		}
		int exit_code = pclose(fp);
		char status[256];
#ifdef _WIN32
		snprintf(status, sizeof(status), "Exit Code: %d\n", exit_code);
#else
		snprintf(status, sizeof(status), "Exit Code: %d\n", WEXITSTATUS(exit_code));
#endif
		send_message(chat_id, status, db, token);

		if (output_size > 0) {
			// Telegram 单条消息最多4096字符，超长就截断
			if (output_size > 4000) {
				memcpy(output + 4000 - 15, "\n... (truncated)", 16);
				output[4000] = '\0';
			}
			send_message(chat_id, output, db, token);
		}

		if (output) free(output);
	}
}

int main() {
#ifdef _WIN32
	system("chcp 65001");
#endif
	// 从环境变量获取 token
	const char *token = getenv("TG_BOT_TOKEN");
	if (token && *token) {
		fprintf(stderr, "[INFO] Bot token loaded from environment\n");
	} else {
		fprintf(stderr, "[FATAL] TG_BOT_TOKEN environment variable not set!\n");
		return 1;
	}

	// 打开数据库
	sqlite3 *db;
	if (sqlite3_open(DB_FILE, &db) == SQLITE_OK) {
		fprintf(stderr, "[INFO] Database opened: %s\n", DB_FILE);
	} else {
		fprintf(stderr, "[FATAL] Can't open database: %s\n", sqlite3_errmsg(db));
		return 1;
	}

	// 创建表如果不存在
	const char *sql = "CREATE TABLE IF NOT EXISTS messages (id INTEGER PRIMARY KEY, chat_id INTEGER, text TEXT, is_bot INTEGER);";
	char *err_msg = NULL;
	if (sqlite3_exec(db, sql, NULL, NULL, &err_msg) == SQLITE_OK) {
		fprintf(stderr, "[INFO] Messages table ready\n");
	} else {
		fprintf(stderr, "[ERROR] SQL error creating table: %s\n", err_msg);
		sqlite3_free(err_msg);
	}

	// 设置信号处理：优雅退出
	signal(SIGINT, signal_handler);
	signal(SIGTERM, signal_handler);

	// 长轮询循环
	long long offset = 0;
	while (keep_running) {
		CURL *curl = init_curl_with_options();
		if (!curl) goto loop_end;

		MemoryStruct chunk = {malloc(1), 0};
		if (!chunk.memory) {
			fprintf(stderr, "[ERROR] Failed to malloc in main loop\n");
			curl_easy_cleanup(curl);
			goto loop_end;
		}

		// 构建 getUpdates URL
		char url[512];
		snprintf(url, sizeof(url), "%s%s/getUpdates?offset=%lld&timeout=30", API_BASE, token, offset);
		fprintf(stderr, "[INFO] Polling updates with offset %lld\n", offset);

		curl_easy_setopt(curl, CURLOPT_URL, url);
		curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
		curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);

		CURLcode res = curl_easy_perform(curl);
		if (res != CURLE_OK) {
			fprintf(stderr, "[ERROR] CURL perform failed in main: %s\n", curl_easy_strerror(res));
		} else {
			long http_code = 0;
			curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
			if (http_code != 200) {
				fprintf(stderr, "[ERROR] Telegram getUpdates returned HTTP %ld\n", http_code);
			} else {
				cJSON *json = cJSON_Parse(chunk.memory);
				if (json) {
					cJSON *result = cJSON_GetObjectItem(json, "result");
					if (result && cJSON_IsArray(result)) {
						fprintf(stderr, "[INFO] Received %d updates\n", cJSON_GetArraySize(result));
						cJSON *item;
						cJSON_ArrayForEach(item, result) {
							process_update(item, db, token);
							cJSON *update_id_item = cJSON_GetObjectItem(item, "update_id");
							if (update_id_item && cJSON_IsNumber(update_id_item)) {
								long long update_id = (long long)update_id_item->valueint;
								if (update_id >= offset) offset = update_id + 1;
							}
						}
					}
					cJSON_Delete(json);
				} else {
					fprintf(stderr, "[ERROR] Failed to parse JSON in main: %s\n", chunk.memory);
				}
			}
		}
		free(chunk.memory);
		curl_easy_cleanup(curl);

		loop_end:
#ifdef _WIN32
		int total_sleep_ms = POLL_INTERVAL * 1000;
		while (total_sleep_ms > 0 && keep_running) {
			// Windows: 拆成小块睡，200ms 粒度
			int sleep_slice_ms = (total_sleep_ms > 200) ? 200 : total_sleep_ms;
			Sleep(sleep_slice_ms);
			total_sleep_ms -= sleep_slice_ms;
		}
#else
		// Linux：直接 sleep
		if (keep_running) sleep(POLL_INTERVAL);
#endif
	}

	// 清理
	sqlite3_close(db);
	fprintf(stderr, "[INFO] Bot shutdown complete.\n");
	return 0;
}
