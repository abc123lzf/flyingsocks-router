//
// Created by lzf on 2021/2/20.
//
#ifndef FS_BOOT_H
#define FS_BOOT_H

#ifdef _WIN32
#error "WINDOWS NOT SUPPORT !"
#endif

#ifdef __cplusplus
extern "C" {
#endif

#ifdef DEBUG
#define FS_VERSION "v3.0-debug"
#else
#define FS_VERSION "v3.0-release"
#endif

#define FS_CFG_LOGGER_DEFAULT_PATH "/var/log"
#define FS_CFG_LOGGER_DEFAULT_LEVEL "INFO"
#define FS_CFG_LOGGER_NAME "logger.conf"
#define FS_CFG_SERVICE_NAME "service.conf"
#define FS_CFG_SERVER_NAME "server.conf"

#define FS_CFG_SERVICE_DEFAULT_TCP_PORT 17020
#define FS_CFG_SERVICE_DEFAULT_UDP_PORT 17021

#define FS_EXIT_SERVER_CONF_NOT_FOUND 1000
#define FS_EXIT_SERVER_CONF_ERROR 1001

#ifdef __cplusplus
}
#endif
#endif
