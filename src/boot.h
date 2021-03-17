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

#include <stdbool.h>

#ifdef DEBUG
#define FS_VERSION "v1.0-debug"
#else
#define FS_VERSION "v1.0-release"
#endif

#define FS_BUILD_TIME __DATE__ " " __TIME__

#define FS_CFG_LOGGER_DEFAULT_PATH "/var/log"
#define FS_CFG_LOGGER_DEFAULT_LEVEL "INFO"
#define FS_CFG_LOGGER_NAME "logger.conf"
#define FS_CFG_SERVICE_NAME "service.conf"
#define FS_CFG_SERVER_NAME "server.conf"
#define FS_CFG_IP_WHITELIST "whitelist.txt"

#define FS_CFG_SERVICE_DEFAULT_TCP_PORT 17020
#define FS_CFG_SERVICE_DEFAULT_UDP_PORT 17021
#define FS_CFG_SERVICE_DEFAULT_DNS_PORT 53

#define FS_EXIT_SERVER_CONF_NOT_FOUND 1000
#define FS_EXIT_SERVER_CONF_ERROR 1001

struct service_config_s {
    // PAC模式
    int pac_mode;
    // 是否打开TCP代理
    bool enable_tcp;
    // TCP代理端口
    unsigned short tcp_port;
    // 是否打开UDP端口
    bool enable_udp;
    // UDP代理端口
    unsigned short udp_port;
    // DNS服务端口
    unsigned short dns_port;
};

// 本地代理服务配置
typedef struct service_config_s service_config_t;





#ifdef __cplusplus
}
#endif
#endif
