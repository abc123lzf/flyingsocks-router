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

#include "boot.h"
#include "buffer.h"
#include "misc.h"
#include "pac.h"
#include <stdbool.h>
#include <event2/event.h>

#define FS_EXIT_TCP_BIND_FAILURE 2000

#define FS_SERVICE_MAX_LISTEN_NUM 8192

struct service_config_s;

// 代理客户端连接上下文
typedef struct client_ctx_s client_ctx_t;
// 本地代理服务上下文
typedef struct service_ctx_s service_ctx_t;

/**
 * 初始化本地代理服务
 * @param config 配置
 * @return 本地代理服务上下文
 */
extern service_ctx_t* proxy_service_init(service_config_t* config, struct event_base* event_base);

/**
 * 运行本地代理服务
 * @param ctx 本地代理服务上下文
 */
extern void proxy_service_run(service_ctx_t* ctx);

/**
 * 停止本地代理服务
 * @param ctx 本地代理服务上下文
 */
extern int proxy_service_stop(service_ctx_t* ctx);

/**
 * client_ctx_s发布订阅回调函数
 */
typedef void (*client_ctx_publish_cb)(client_ctx_t* client_ctx, void* arg);

/**
 * 注册客户端上下文发布回调
 * @param ctx 客户端连接上下文
 * @param publish_cb 发布回调
 * @param accept_need_proxy 是否接收经过PAC判断需要代理的客户端连接上下文
 * @param arg 用户参数
 * @return 是否注册成功
 */
extern bool proxy_service_register_client_ctx_publish_cb(service_ctx_t* ctx, client_ctx_publish_cb publish_cb,
                                                         bool accept_need_proxy, void* arg);

//代理客户端连接关闭时的回调
typedef void (*client_close_callback_fn)(client_ctx_t*, void*);

/**
 * 代理传输层协议
 */
enum proxy_protocol_e {
    PROTOCOL_TCP, PROTOCOL_UDP
};

typedef enum proxy_protocol_e proxy_protocol_t;

/**
 * 获取目标服务器地址
 * @param ctx 客户端连接上下文
 * @return 目标服务器地址
 */
extern struct sockaddr_in* client_ctx_get_target_server_address(client_ctx_t* ctx);

/**
 * 获取代理传输层协议
 * @param ctx 客户端连接上下文
 * @return 协议 TCP或者UDP
 */
extern proxy_protocol_t client_ctx_get_proxy_protocol(client_ctx_t* ctx);

/**
 * 向客户端写响应数据
 * @param ctx 客户端连接上下文
 * @param buf 响应数据
 * @return 已写入数据字节数
 */
extern int client_ctx_write_data(client_ctx_t* ctx, byte_buf_t* buf);

/**
 * 设置客户端连接被关闭时的回调函数
 * @param ctx 客户端连接上下文
 * @param callback_fn 回调函数指针
 * @param cb_arg 回调函数的用户参数
 * @return 回调函数是否设置成功
 */
extern bool client_ctx_put_close_callback(client_ctx_t* ctx, client_close_callback_fn callback_fn, void* cb_arg);

/**
 * 设置客户端请求数据接收者
 * @param ctx 客户端连接上下文
 * @param receiver
 * @return
 */
extern bool client_ctx_set_msg_receiver(client_ctx_t* ctx, msg_deliver_receiver_t* receiver);

/**
 * 释放客户端连接上下文，该操作会关闭客户端连接
 * @param ctx 客户端连接上下文
 */
extern void client_ctx_free(client_ctx_t* ctx);

#ifdef __cplusplus
}
#endif
#endif
