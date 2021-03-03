//
// Created by lzf on 2021/2/20.
//
#ifndef FS_LOGGER_H
#define FS_LOGGER_H

#ifdef __cplusplus
extern "C" {
#endif

#include "misc.h"
#include <stdio.h>
#include <stdbool.h>
#include <string.h>

#define FS_LOGGER_LEVEL_NONE (-1)
#define FS_LOGGER_LEVEL_ERROR 0
#define FS_LOGGER_LEVEL_WARN 1
#define FS_LOGGER_LEVEL_INFO 2
#define FS_LOGGER_LEVEL_DEBUG 3
#define FS_LOGGER_LEVEL_TRACE 4

typedef int log_level_t;

struct logger_config_s {
    string_t* file_path;
    log_level_t level;
    bool open_stdout;
};

typedef struct logger_config_s logger_config_t;

extern int logger_initial(logger_config_t *ctx);

extern void log_error(const char *msg, ...);
extern void log_warn(const char *msg, ...);
extern void log_info(const char *msg, ...);
extern void log_debug(const char *msg, ...);
extern void log_trace(const char *msg, ...);

#ifdef __cplusplus
}
#endif

#endif //FS_ROUTER_LOGGER_H
