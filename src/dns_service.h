//
// Created by lzf on 2021/3/4.
//

#ifndef FS_DNS_SERVICE_H
#define FS_DNS_SERVICE_H

#include <stdint.h>
#include <event2/event.h>
#include <event2/dns.h>
#include <event2/dns_struct.h>


typedef struct dns_config_s {
    // DNS服务端口
    uint16_t port;

} dns_config_t;

typedef struct dns_ctx_s dns_ctx_t;

typedef struct dns_client_ctx_s dns_client_ctx_t;

/**
 * 启动DNS服务器
 * @param config DNS服务配置
 * @param base 共享的event_base，可为NULL
 * @return DNS服务器上下文
 */
extern dns_ctx_t* dns_service_initial(dns_config_t* config, struct event_base* base);

/**
 * 停止DNS服务
 */
extern void dns_service_stop(dns_ctx_t* ctx);

/**
 * DNS请求发布回调函数定义
 */
typedef void (*dns_client_ctx_publish_cb)(dns_client_ctx_t* client_ctx, void* arg);

/**
 * 注册DNS请求订阅者
 * @param ctx DNS请求上下文
 * @param cb 回调函数
 * @param arg 回调函数用户参数
 */
extern void dns_service_register_client_ctx_publish_cb(dns_ctx_t* ctx, dns_client_ctx_publish_cb cb, void* arg);

/**
 * DNS请求详情
 */
typedef struct evdns_server_request dns_client_request_t;

/**
 * 获取DNS请求详情
 * @param ctx DNS客户端上下文
 * @return DNS请求详情
 */
extern dns_client_request_t* dns_service_client_ctx_get_request(dns_client_ctx_t* ctx);

#define FS_DNS_SECTION_ANSWER EVDNS_ANSWER_SECTION
#define FS_DNS_SECTION_AUTHORITY EVDNS_AUTHORITY_SECTION
#define FS_DNS_SECTION_ADDITIONAL EVDNS_ADDITIONAL_SECTION

/**
 * 设置DNS响应中的FLAG字段
 * @param client_ctx DNS请求者上下文
 * @param flag 16位的FLAG值
 */
extern void dns_service_client_ctx_set_flag(dns_client_ctx_t* client_ctx, unsigned short flag);

/**
 * 添加DNS回复信息
 * @param client_ctx DNS请求者上下文
 * @param section SECTION类型，包含Answer/Authority/Additional-Information
 * @param name 回复内容
 * @param type 类型
 * @param class 类
 * @param ttl Time To Live
 * @param data 额外数据，可为NULL
 */
extern void dns_service_client_ctx_add_reply(dns_client_ctx_t* client_ctx, int section, char* name,
                                             int type, int class, int ttl, byte_buf_t* data);

/**
 * 向客户端发送DNS响应，并关闭当前DNS客户端上下文
 * @param client_ctx DNS客户端上下文
 * @param err 错误代码，如果正确响应则为0，参考event2/dns.h中的DNS_ERR开头的宏
 */
extern void dns_service_client_ctx_finish(dns_client_ctx_t* client_ctx, int err);

/**
 * 不发送响应，直接关闭DNS客户端上下文
 * @param client_ctx DNS客户端上下文
 */
extern void dns_service_client_ctx_discard(dns_client_ctx_t* client_ctx);


#endif