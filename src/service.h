//
// Created by lzf on 2021/2/21.
//
// Local proxy service interface
//

#ifndef FS_SERVICE_H
#define FS_SERVICE_H

#ifdef __cplusplus
extern "C" {
#endif

#include "buffer.h"
#include "misc.h"
#include <stdbool.h>
#include <event2/event.h>

#define FS_EXIT_TCP_BIND_FAILURE 2000
#define FS_SERVICE_PAC_MODE_NONE 0
#define FS_SERVICE_PAC_MODE_IP 1
#define FS_SERVICE_PAC_MODE_GLOBAL 2

#define FS_SERVICE_MAX_LISTEN_NUM 500

// 本地代理服务配置
typedef struct service_config_s service_config_t;
struct service_config_s {
    int pac_mode;
    bool enable_tcp;
    unsigned short tcp_port;
    bool enable_udp;
    unsigned short udp_port;
};

// 代理客户端连接上下文
typedef struct client_ctx_s client_ctx_t;
// 本地代理服务上下文
typedef struct service_ctx_s service_ctx_t;

extern service_ctx_t* proxy_service_init(service_config_t* config);
extern void proxy_service_run(service_ctx_t* ctx);
extern int proxy_service_stop(service_ctx_t* ctx);

// client_ctx_s发布订阅
typedef void (*client_ctx_publish_cb)(client_ctx_t* client_ctx, void* arg);
extern bool proxy_service_register_client_ctx_publish_cb(service_ctx_t* ctx, client_ctx_publish_cb publish_cb,
                                                         bool accept_need_proxy, void* arg);

//代理客户端连接关闭时的回调
typedef void (*client_close_callback_fn)(client_ctx_t*, void*);

enum proxy_protocol_e {
    TCP, UDP
};

typedef enum proxy_protocol_e proxy_protocol_t;

extern struct sockaddr_in* client_ctx_get_target_server_address(client_ctx_t* ctx);
extern proxy_protocol_t client_ctx_get_proxy_protocol(client_ctx_t* ctx);
extern int client_ctx_write_data(client_ctx_t* ctx, byte_buf_t* buf);
extern bool client_ctx_put_close_callback(client_ctx_t* ctx, client_close_callback_fn callback_fn, void* cb_arg);
extern bool client_ctx_set_msg_receiver(client_ctx_t* ctx, msg_deliver_receiver_t* receiver);
extern void client_ctx_free(client_ctx_t* ctx);

#ifdef __cplusplus
}
#endif
#endif
