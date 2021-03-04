//
// Created by lzf on 2021/2/26.
//

#ifndef FS_SERVER_FORWARD_H
#define FS_SERVER_FORWARD_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include "service.h"

#define FS_EXIT_AUTH_FAILURE 3000
#define FS_EXIT_AUTH_MSG_DECODE_ERROR 3001
#define FS_EXIT_PROXY_MSG_TOO_LARGE 3002
#define FS_EXIT_SSL_NOT_SUPPORT 3003

typedef enum server_auth_type_e {
    // 简单认证
    AUTH_TYPE_SIMPLE,

    // 用户认证
    AUTH_TYPE_USER
} server_auth_type_t;

typedef enum server_encrypt_type_e {
    // 不加密
    ENCRYPT_TYPE_NONE,

    // OpenSSL(TLSv1.2)加密
    ENCRYPT_TYPE_OPENSSL
} server_encrypt_type_t;

struct server_config_s {
    // 主机名，IP地址或者域名
    char *hostname;

    // 代理服务端口
    uint16_t port;

    // 认证类型
    server_auth_type_t auth_type;

    // 加密类型
    server_encrypt_type_t encrypt_type;

    // 认证参数
    string_t* auth_argument;
};

typedef struct server_config_s server_config_t;
typedef struct server_ctx_s server_ctx_t;

extern server_ctx_t* server_forward_initial(server_config_t *config, service_ctx_t* service_ctx);

extern void server_forward_run(server_ctx_t *ctx);

extern void server_forward_stop(server_ctx_t *ctx);

#ifdef __cplusplus
}
#endif

#endif
