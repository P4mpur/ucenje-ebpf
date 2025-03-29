#pragma once

#include <stdio.h>

enum log_level {
    LOG_DEBUG,
    LOG_INFO,
    LOG_WARN,
    LOG_ERROR,
};

void log_init(const char *program_name, int use_syslog, const char *log_file_path);
void log_set_level(enum log_level level);
void log_close();
void log_block(enum log_level level, const char *header, const char *block);

void log_msg(enum log_level level, const char *fmt, ...);

#define LOGD(...) log_msg(LOG_DEBUG, __VA_ARGS__)
#define LOGI(...) log_msg(LOG_INFO,  __VA_ARGS__)
#define LOGW(...) log_msg(LOG_WARN,  __VA_ARGS__)
#define LOGE(...) log_msg(LOG_ERROR, __VA_ARGS__)
