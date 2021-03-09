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

/* 日志级别 */
typedef int log_level_t;

struct logger_config_s {
    // 日志输出路径
    string_t* file_path;

    // 日志输出级别
    log_level_t level;

    //是否向标准输出流输出日志
    bool open_stdout;
};

typedef struct logger_config_s logger_config_t;

/**
 * 初始化日志组件
 * @param ctx 日志配置
 * @return 初始化结果
 */
extern int logger_initial(logger_config_t *ctx);

/**
 * 打印错误日志
 * @param msg 日志字符串模板
 * @param ... 日志参数
 */
extern void logger_error(const char *msg, ...);

/**
 * 打印警告日志
 * @param msg 日志字符串模板
 * @param ... 日志参数
 */
extern void logger_warn(const char *msg, ...);

/**
 * 打印常规提示日志
 * @param msg 日志字符串模板
 * @param ... 日志参数
 */
extern void logger_info(const char *msg, ...);

/**
 * 打印调试日志
 * @param msg 日志字符串模板
 * @param ... 日志参数
 */
extern void logger_debug(const char *msg, ...);

/**
 * 打印进度跟踪日志
 * @param msg 日志字符串模板
 * @param ... 日志参数
 */
extern void logger_trace(const char *msg, ...);

#ifndef FS_FILE_NAME
#define FS_FILE_NAME (strrchr(__FILE__, '/') ? strrchr(__FILE__, '/') + 1 : __FILE__)
#endif

/** 日志处理宏，添加函数名和行号 */
#define log_error(msg, ...) \
    logger_error(msg " --> (%s:%d %s)", ##__VA_ARGS__, FS_FILE_NAME, __LINE__, __func__)

#define log_warn(msg, ...) \
    logger_warn(msg " --> (%s:%d %s)", ##__VA_ARGS__, FS_FILE_NAME, __LINE__, __func__)

#define log_info(msg, ...) \
    logger_info(msg " --> (%s:%d %s)", ##__VA_ARGS__, FS_FILE_NAME, __LINE__, __func__)

#define log_debug(msg, ...) \
    logger_debug(msg " --> (%s:%d %s)", ##__VA_ARGS__, FS_FILE_NAME, __LINE__, __func__)

#define log_trace(msg, ...) \
    logger_trace(msg " --> (%s:%d %s)", ##__VA_ARGS__, FS_FILE_NAME, __LINE__, __func__)

#ifdef __cplusplus
}
#endif

#endif //FS_ROUTER_LOGGER_H
