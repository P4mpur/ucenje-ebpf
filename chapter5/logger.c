#include "logger.h"
#include <stdarg.h>
#include <time.h>
#include <string.h>
#include <syslog.h>
#include <stdlib.h>

static int log_to_syslog = 0;
static enum log_level current_level = LOG_INFO;
static FILE *log_file = NULL;

static const char *level_names[] = {
    "DEBUG", "INFO", "WARN", "ERROR"
};

void log_init(const char *program_name, int use_syslog_flag, const char *log_file_path) {
    log_to_syslog = use_syslog_flag;

    if (log_to_syslog) {
        openlog(program_name, LOG_PID | LOG_CONS, LOG_USER);
    }

    if (log_file_path) {
        log_file = fopen(log_file_path, "a");
        if (!log_file) {
            fprintf(stderr, "[logger] Failed to open log file: %s\n", log_file_path);
        }
    }
}

void log_set_level(enum log_level level) {
    current_level = level;
}

void log_close() {
    if (log_to_syslog) {
        closelog();
    }

    if (log_file) {
        fclose(log_file);
        log_file = NULL;
    }
}

void log_msg(enum log_level level, const char *fmt, ...) {
    if (level < current_level) return;

    va_list args;
    va_start(args, fmt);

    // Build timestamp
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    char time_buf[20];
    strftime(time_buf, sizeof(time_buf), "%F %T", tm_info);

    // Format message
    char message[1024];
    vsnprintf(message, sizeof(message), fmt, args);

    // syslog
    if (log_to_syslog) {
        int priority = LOG_INFO;
        if (level == LOG_DEBUG) priority = LOG_DEBUG;
        else if (level == LOG_WARN) priority = LOG_WARNING;
        else if (level == LOG_ERROR) priority = LOG_ERR;

        syslog(priority, "%s", message);
    }

    // stderr (always prints if not syslog or file)
    if (!log_to_syslog && !log_file) {
        fprintf(stderr, "[%s] %-5s: %s\n", time_buf, level_names[level], message);
    }

    // custom file
    if (log_file) {
        fprintf(log_file, "[%s] %-5s: %s\n", time_buf, level_names[level], message);
        fflush(log_file);
    }

    va_end(args);
}

void log_block(enum log_level level, const char *header, const char *block) {
    if (level < current_level) return;

    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    char time_buf[20];
    strftime(time_buf, sizeof(time_buf), "%F %T", tm_info);

    if (log_file) {
        fprintf(log_file, "[%s] %-5s: %s\n%s\n", time_buf, level_names[level], header, block);
        fflush(log_file);
    } else if (log_to_syslog) {
        syslog(LOG_INFO, "%s\n%s", header, block);
    } else {
        fprintf(stderr, "[%s] %-5s: %s\n%s\n", time_buf, level_names[level], header, block);
    }
}

