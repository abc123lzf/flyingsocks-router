//
// Created by lzf on 2021/2/20.
//
#include "logger.h"
#include <string.h>
#include <stdarg.h>
#include <stdlib.h>
#include <event2/event.h>
#include <time.h>

typedef struct logger_ctx_s {
    FILE* log_file;
    log_level_t log_level;
    bool open_stdout;
} logger_ctx_t;

#define FS_LOGGER_DEFAULT_FILE_NAME "fs-client.log"
#define FS_LOGGER_LINE_SEPARATOR "\n"

static void print_stdout(log_level_t level, const char* msg, va_list args);
static void print_file(log_level_t level, FILE* file, const char* msg, va_list args);
static void header_tag(log_level_t level, char* dst);

static bool logger_init = false;
static logger_ctx_t logger_ctx = {0};

int logger_initial(logger_config_t* ctx) {
    const char* file_path = string_get_content(ctx->file_path);
    size_t len = strlen(file_path);

    if (file_path[len - 1] == '/') {
        char* str = malloc(len + strlen(FS_LOGGER_DEFAULT_FILE_NAME) + 1);
        strcpy(str, file_path);
        strcat(str, FS_LOGGER_DEFAULT_FILE_NAME);
        file_path = str;
    } else {
        char* str = malloc(len + strlen(FS_LOGGER_DEFAULT_FILE_NAME) + 2);
        strcpy(str, file_path);
        strcat(str, "/");
        strcat(str, FS_LOGGER_DEFAULT_FILE_NAME);
        file_path = str;
    }

    FILE* file = fopen(file_path, "a");
    if (file == NULL) {
        return 1;
    }

    logger_ctx.log_file = file;
    logger_ctx.log_level = ctx->level;
    logger_ctx.open_stdout = ctx->open_stdout;
    logger_init = true;
    return 0;
}


void logger_error(const char* msg, ...) {
    if (!logger_init || logger_ctx.log_level < FS_LOGGER_LEVEL_ERROR) {
        return;
    }

    va_list va0;
    va_start(va0, msg);

    if (logger_ctx.open_stdout) {
        va_list va1;
        va_copy(va1, va0);
        print_file(FS_LOGGER_LEVEL_ERROR, logger_ctx.log_file, msg, va1);
        va_end(va1);
        print_stdout(FS_LOGGER_LEVEL_ERROR, msg, va0);
    } else {
        print_file(FS_LOGGER_LEVEL_ERROR, logger_ctx.log_file, msg, va0);
    }

    va_end(va0);
}

void logger_warn(const char* msg, ...) {
    if (!logger_init || logger_ctx.log_level < FS_LOGGER_LEVEL_WARN) {
        return;
    }
    va_list va0;
    va_start(va0, msg);

    if (logger_ctx.open_stdout) {
        va_list va1;
        va_copy(va1, va0);
        print_file(FS_LOGGER_LEVEL_WARN, logger_ctx.log_file, msg, va1);
        va_end(va1);
        print_stdout(FS_LOGGER_LEVEL_WARN, msg, va0);
    } else {
        print_file(FS_LOGGER_LEVEL_WARN, logger_ctx.log_file, msg, va0);
    }

    va_end(va0);
}

void logger_info(const char* msg, ...) {
    if (!logger_init || logger_ctx.log_level < FS_LOGGER_LEVEL_INFO) {
        return;
    }
    va_list va0;
    va_start(va0, msg);

    if (logger_ctx.open_stdout) {
        va_list va1;
        va_copy(va1, va0);
        print_file(FS_LOGGER_LEVEL_INFO, logger_ctx.log_file, msg, va1);
        va_end(va1);
        print_stdout(FS_LOGGER_LEVEL_INFO, msg, va0);
    } else {
        print_file(FS_LOGGER_LEVEL_INFO, logger_ctx.log_file, msg, va0);
    }

    va_end(va0);
}

void logger_debug(const char* msg, ...) {
    if (!logger_init || logger_ctx.log_level < FS_LOGGER_LEVEL_DEBUG) {
        return;
    }
    va_list va0;
    va_start(va0, msg);

    if (logger_ctx.open_stdout) {
        va_list va1;
        va_copy(va1, va0);
        print_file(FS_LOGGER_LEVEL_DEBUG, logger_ctx.log_file, msg, va1);
        va_end(va1);
        print_stdout(FS_LOGGER_LEVEL_DEBUG, msg, va0);
    } else {
        print_file(FS_LOGGER_LEVEL_DEBUG, logger_ctx.log_file, msg, va0);
    }

    va_end(va0);
}

void logger_trace(const char* msg, ...) {
    if (!logger_init || logger_ctx.log_level < FS_LOGGER_LEVEL_TRACE) {
        return;
    }
    va_list va0;
    va_start(va0, msg);

    if (logger_ctx.open_stdout) {
        va_list va1;
        va_copy(va1, va0);
        print_file(FS_LOGGER_LEVEL_TRACE, logger_ctx.log_file, msg, va1);
        va_end(va1);
        print_stdout(FS_LOGGER_LEVEL_TRACE, msg, va0);
    } else {
        print_file(FS_LOGGER_LEVEL_TRACE, logger_ctx.log_file, msg, va0);
    }

    va_end(va0);
}

static inline void print_stdout(log_level_t level, const char* msg, va_list args) {
    if (msg == NULL) {
        return;
    }

    char tag[35];
    header_tag(level, tag);
    printf("%s", tag);
    vprintf(msg, args);
    printf(FS_LOGGER_LINE_SEPARATOR);
}

static inline void print_file(log_level_t level, FILE* file, const char* msg, va_list args) {
    if (msg == NULL) {
        return;
    }

    char tag[35];
    header_tag(level, tag);
    fputs(tag, file);
    vfprintf(file, msg, args);
    fputs(FS_LOGGER_LINE_SEPARATOR, file);
    fflush(file);
}

static inline void header_tag(log_level_t level, char* dst) {
    struct timeval now;
    gettimeofday(&now, NULL);

    struct tm* time = localtime(&now.tv_sec);

    char* level_tag;
    switch (level) {
        case FS_LOGGER_LEVEL_ERROR: level_tag = "ERROR"; break;
        case FS_LOGGER_LEVEL_WARN: level_tag = "WARN"; break;
        case FS_LOGGER_LEVEL_INFO: level_tag = "INFO"; break;
        case FS_LOGGER_LEVEL_DEBUG: level_tag = "DEBUG"; break;
        case FS_LOGGER_LEVEL_TRACE: level_tag = "TRACE"; break;
        default:
            level_tag = "UNKNOWN";
    }

    sprintf(dst, "<%04d-%02d-%02d %02d:%02d:%02d,%03ld>[%5s] ", time->tm_year + 1900, time->tm_mon + 1,
            time->tm_mday, time->tm_hour, time->tm_min, time->tm_sec, now.tv_usec / 1000, level_tag);
}