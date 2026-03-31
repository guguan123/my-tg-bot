# 编译器设置
CC = gcc
CFLAGS = -Wall -Wextra -O2
LIBS = -lcurl -lcjson -lsqlite3

# 目标程序名
BUILD_DIR = build
TARGET = $(BUILD_DIR)/tg_bot

# 源文件
SRCS = tg_bot.c

# 默认构建目标
all: $(BUILD_DIR) $(TARGET)

# 确保目录存在
$(BUILD_DIR):
ifeq ($(OS),Windows_NT)
	if not exist $(BUILD_DIR) mkdir $(BUILD_DIR)
else
	mkdir -p $(BUILD_DIR)
endif

# 编译指令
$(TARGET): $(SRCS)
	$(CC) $(CFLAGS) $(SRCS) -o $(TARGET) $(LIBS)

# 调试版本：包含 gdb 调试信息
debug: CFLAGS += -g -DDEBUG
debug: all

# 静态编译建议
static: CFLAGS += -static
static: LIBS += -lpthread -ldl -lm -lz
static: all

# 清理构建目录
clean:
ifeq ($(OS),Windows_NT)
	if exist $(BUILD_DIR) rmdir /s /q $(BUILD_DIR)
else
	rm -r $(BUILD_DIR)
endif

.PHONY: all debug clean static
