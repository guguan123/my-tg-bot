#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <curl/curl.h>
#include <cjson/cJSON.h>
#include <sqlite3.h>

#ifdef _WIN32
#include <windows.h>  // 用于 Sleep on Windows
#define sleep(ms) Sleep((ms) * 1000)  // Windows Sleep 是毫秒，兼容 Unix sleep(秒)
#else
#include <unistd.h>  // 用于 sleep on Unix-like
#endif

#define API_BASE "https://api.telegram.org/bot"
#define DB_FILE "tg_bot.db"

// 内存结构，用于 CURL 回调收集响应
typedef struct {
	char *memory;
	size_t size;
} MemoryStruct;

// CURL 写回调函数：收集 HTTP 响应数据
static size_t write_callback(void *contents, size_t size, size_t nmemb, void *userp) {
	size_t realsize = size * nmemb;
	MemoryStruct *mem = (MemoryStruct *)userp;
	char *ptr = realloc(mem->memory, mem->size + realsize + 1);
	if (ptr == NULL) {
		fprintf(stderr, "[ERROR] realloc failed in write_callback\n");
		return 0;  // 内存分配失败，返回 0 表示错误
	}
	mem->memory = ptr;
	memcpy(&(mem->memory[mem->size]), contents, realsize);
	mem->size += realsize;
	mem->memory[mem->size] = 0;
	return realsize;
}

// 初始化 CURL 并设置通用选项，包括 CA 证书和代理日志
CURL *init_curl_with_options() {
	CURL *curl = curl_easy_init();
	if (!curl) {
		fprintf(stderr, "[ERROR] Failed to init CURL\n");
		return NULL;
	}

	// 处理 Windows 等环境的 CA 证书问题，从环境变量 CURL_CA_BUNDLE 读取路径
	const char *ca_path = getenv("CURL_CA_BUNDLE");
	if (ca_path) {
		curl_easy_setopt(curl, CURLOPT_CAINFO, ca_path);
		fprintf(stderr, "[INFO] Using CA bundle from env: %s\n", ca_path);
	} else {
#ifdef _WIN32
		fprintf(stderr, "[WARNING] No CURL_CA_BUNDLE set, may have SSL cert issues on Windows. Download cacert.pem and set env var.\n");
#endif
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

	// URL 编码 text，使用 libcurl 自带的 escape 函数
	char *escaped_text = curl_easy_escape(curl, text, 0);
	if (!escaped_text) {
		fprintf(stderr, "[ERROR] Failed to escape text in send_message\n");
		curl_easy_cleanup(curl);
		return;
	}

	// 构建 POST fields
	char postfields[1024];
	snprintf(postfields, sizeof(postfields), "chat_id=%lld&text=%s", chat_id, escaped_text);
	curl_free(escaped_text);  // 释放 escaped_text

	curl_easy_setopt(curl, CURLOPT_URL, url);
	curl_easy_setopt(curl, CURLOPT_POSTFIELDS, postfields);

	// 执行请求
	CURLcode res = curl_easy_perform(curl);
	if (res != CURLE_OK) {
		fprintf(stderr, "\n[ERROR] CURL perform failed in send_message: %s\n", curl_easy_strerror(res));
	} else {
		// 检查 HTTP 状态码
		long http_code = 0;
		curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
		if (http_code != 200) {
			fprintf(stderr, "\n[ERROR] Telegram API returned HTTP %ld in send_message\n", http_code);
		} else {
			fprintf(stderr, "\n[INFO] Message sent successfully to chat_id %lld\n", chat_id);
		}
	}
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
	if (sqlite3_step(stmt) != SQLITE_DONE) {
		fprintf(stderr, "[ERROR] Failed to execute SQL in send_message: %s\n", sqlite3_errmsg(db));
	} else {
		fprintf(stderr, "[INFO] Message logged to DB for chat_id %lld\n", chat_id);
	}
	sqlite3_finalize(stmt);
}

// 执行 CURL 请求函数：获取 URL 内容，支持 IPv4/6 和 headers
char *perform_curl(const char *url, int ipv4, int ipv6, int include_headers) {
	CURL *curl = init_curl_with_options();
	if (!curl) return strdup("CURL init error!");

	MemoryStruct chunk = {malloc(1), 0};
	if (!chunk.memory) {
		fprintf(stderr, "[ERROR] Failed to malloc in perform_curl\n");
		curl_easy_cleanup(curl);
		return strdup("Memory error!");
	}

	fprintf(stderr, "[INFO] Performing CURL to: %s (IPv4: %d, IPv6: %d, Headers: %d)\n", url, ipv4, ipv6, include_headers);

	curl_easy_setopt(curl, CURLOPT_URL, url);
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);

	if (include_headers) curl_easy_setopt(curl, CURLOPT_HEADER, 1L);
	if (ipv4) curl_easy_setopt(curl, CURLOPT_IPRESOLVE, CURL_IPRESOLVE_V4);
	else if (ipv6) curl_easy_setopt(curl, CURLOPT_IPRESOLVE, CURL_IPRESOLVE_V6);

	CURLcode res = curl_easy_perform(curl);
	if (res != CURLE_OK) {
		fprintf(stderr, "[ERROR] CURL perform failed: %s\n", curl_easy_strerror(res));
		free(chunk.memory);
		chunk.memory = strdup("CURL error!");
	} else {
		long http_code = 0;
		curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
		if (http_code != 200) {
			fprintf(stderr, "[WARNING] HTTP code %ld from %s\n", http_code, url);
		}
	}
	curl_easy_cleanup(curl);
	return chunk.memory;
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
	long long chat_id = (long long) (chat_id_item ? chat_id_item->valuedouble : 0);

	// 获取 from 和 user_id
	cJSON *from = cJSON_GetObjectItem(message, "from");
	if (!from) return;
	cJSON *user_id_item = cJSON_GetObjectItem(from, "id");
	if (!user_id_item || !cJSON_IsNumber(user_id_item)) {
		fprintf(stderr, "[ERROR] Invalid user_id in update\n");
		return;
	}
	long long user_id = (long long) (user_id_item ? user_id_item->valuedouble : 0);

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
	} else if (strncmp(text, "/curl ", 6) == 0) {
		char *args = strdup(text + 6);
		if (!args) {
			fprintf(stderr, "[ERROR] strdup failed in /curl\n");
			return;
		}
		char *url = strtok(args, " ");
		int ipv4 = 0, ipv6 = 0, include_headers = 0;

		char *option;
		while ((option = strtok(NULL, " "))) {
			if (strcmp(option, "-4") == 0) ipv4 = 1;
			else if (strcmp(option, "-6") == 0) ipv6 = 1;
			else if (strcmp(option, "-i") == 0) include_headers = 1;
		}

		if (url) {
			char *response = perform_curl(url, ipv4, ipv6, include_headers);
			// 截断响应如果太长（Telegram 消息限 4096 字符）
			if (strlen(response) > 4000) {
				response[4000] = '\0';
				strcat(response, "... (truncated)");
			}
			send_message(chat_id, response, db, token);
			free(response);
		} else {
			send_message(chat_id, "Usage: /curl https://example.com [-4|-6|-i]", db, token);
		}
		free(args);
	}
}

int main() {
	// 从环境变量获取 token
	const char *token = getenv("TG_BOT_TOKEN");
	if (!token || !*token) {
		fprintf(stderr, "[FATAL] TG_BOT_TOKEN environment variable not set!\n");
		return 1;
	}
	fprintf(stderr, "[INFO] Bot token loaded from environment\n");

	// 打开数据库
	sqlite3 *db;
	if (sqlite3_open(DB_FILE, &db) != SQLITE_OK) {
		fprintf(stderr, "[FATAL] Can't open database: %s\n", sqlite3_errmsg(db));
		return 1;
	}
	fprintf(stderr, "[INFO] Database opened: %s\n", DB_FILE);

	// 创建表如果不存在
	const char *sql = "CREATE TABLE IF NOT EXISTS messages (id INTEGER PRIMARY KEY, chat_id INTEGER, text TEXT, is_bot INTEGER);";
	char *err_msg = NULL;
	if (sqlite3_exec(db, sql, NULL, NULL, &err_msg) != SQLITE_OK) {
		fprintf(stderr, "[ERROR] SQL error creating table: %s\n", err_msg);
		sqlite3_free(err_msg);
	} else {
		fprintf(stderr, "[INFO] Messages table ready\n");
	}

	// 长轮询循环
	long long offset = 0;
	while (1) {
		CURL *curl = init_curl_with_options();
		if (!curl) {
			sleep(2);
			continue;
		}

		MemoryStruct chunk = {malloc(1), 0};
		if (!chunk.memory) {
			fprintf(stderr, "[ERROR] Failed to malloc in main loop\n");
			curl_easy_cleanup(curl);
			sleep(2);
			continue;
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
								long long update_id = (long long) update_id_item->valueint;
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

#ifdef _WIN32
		Sleep((2) * 1000);
#else
		sleep(2);
#endif
	}

	sqlite3_close(db);
	return 0;
}
