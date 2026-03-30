# 编译器设置
CC = gcc
CFLAGS = -Wall -Wextra -O2
LIBS = -lcurl -lcjson -lsqlite3

# 目标程序名
TARGET = tg_bot
# 源文件
SRCS = tg_bot.c

# 默认构建目标
all: $(TARGET)

# 编译指令
$(TARGET): $(SRCS)
	$(CC) $(CFLAGS) $(SRCS) -o $(TARGET) $(LIBS)

# 调试版本：包含 gdb 调试信息
debug: CFLAGS += -g -DDEBUG
debug: all

# 静态编译建议（如果主人在 Alpine 上想做独立二进制文件）
static: CFLAGS += -static
static: LIBS += -lpthread -ldl -lm -lz
static: all

# 清理产生的二进制文件
clean:
	rm -f $(TARGET)

.PHONY: all debug clean static
