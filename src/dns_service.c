//
// Created by lzf on 2021/3/4.
//
#include "logger.h"
#include "dns_service.h"
#include <stdlib.h>
#include <unistd.h>

struct dns_ctx_s {

    struct event_base* event_base;

    // SOCKET描述符
    int dns_fd;

    // DNS服务器对象
    struct evdns_server_port* server;

    // DNS代理请求发布回调
    dns_client_ctx_publish_cb publish_cb;

    // DNS代理请求发布回调用户参数
    void* publish_cb_arg;
};


struct dns_client_ctx_s {
    // 所属的DNS服务器上下文
    dns_ctx_t* server_ctx;

    // DNS请求
    struct evdns_server_request* dns_request;
};

static void request_cb(struct evdns_server_request* request, void* arg);

dns_ctx_t* dns_service_initial(dns_config_t* config, struct event_base* base) {
    if (config == NULL || base == NULL) {
        return NULL;
    }

    dns_ctx_t* ctx = calloc(sizeof(struct dns_ctx_s), 1);
    ctx->event_base = base;
    int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd == -1) {
        log_error("Could not create DNS socket");
        exit(1);
    }

    evutil_make_socket_nonblocking(fd);


    struct sockaddr_in bind_addr;
    bind_addr.sin_family = AF_INET;
    bind_addr.sin_port = htons(config->port);
    bind_addr.sin_addr.s_addr = htonl(INADDR_ANY);

    int res = bind(fd, (const struct sockaddr *) &bind_addr, sizeof(struct sockaddr_in));
    if (res == -1) {
        log_error("Could not bind DNS service port: %d", config->port);
        exit(1);
    }

    ctx->dns_fd = fd;

    struct evdns_server_port* server_port = evdns_add_server_port_with_base(base, fd, 0, request_cb, ctx);
    if (server_port == NULL) {
        log_error("Could not create Libevent DNS server port");
        exit(1);
    }

    ctx->server = server_port;
    return ctx;
}

void dns_service_stop(dns_ctx_t* ctx) {
    evdns_close_server_port(ctx->server);
    close(ctx->dns_fd);
    free(ctx);
}

static void request_cb(struct evdns_server_request* request, void* arg) {
    dns_ctx_t* ctx = (dns_ctx_t*) arg;
    dns_client_ctx_t* client_ctx = malloc(sizeof(dns_client_ctx_t));
    client_ctx->dns_request = request;
    client_ctx->server_ctx = ctx;
    if (ctx->publish_cb != NULL) {
        ctx->publish_cb(client_ctx, ctx->publish_cb_arg);
    } else {
        evdns_server_request_drop(request);
        free(client_ctx);
    }
}


void dns_service_register_client_ctx_publish_cb(dns_ctx_t* ctx, dns_client_ctx_publish_cb cb, void* arg) {
    ctx->publish_cb = cb;
    ctx->publish_cb_arg = arg;
}


dns_client_request_t* dns_service_client_ctx_get_request(dns_client_ctx_t* ctx) {
    return ctx->dns_request;
}

void dns_service_client_ctx_set_flag(dns_client_ctx_t* client_ctx, unsigned short flag) {
    evdns_server_request_set_flags(client_ctx->dns_request, flag);
}


void dns_service_client_ctx_add_reply(dns_client_ctx_t* client_ctx, int section, char* name, int type,
                                      int class, int ttl, byte_buf_t* data) {
    struct evdns_server_request* request = client_ctx->dns_request;
    int data_len = data != NULL ? byte_buf_readable_bytes(data) : 0;
    char tmp[256] = {0, 0};
    if (data != NULL && data_len > 0) {
        byte_buf_read_chars(data, tmp, data_len);
    }

    if (type == EVDNS_TYPE_A) {
        evdns_server_request_add_a_reply(request, name, data_len / 4, tmp, ttl);
    } else if (type == EVDNS_TYPE_AAAA) {
        evdns_server_request_add_aaaa_reply(request, name, data_len / 16, tmp, ttl);
    } else {
        evdns_server_request_add_reply(request, section, name, type, class, ttl, data_len, 0, tmp);
    }
}


void dns_service_client_ctx_finish(dns_client_ctx_t* client_ctx, int err) {
    evdns_server_request_respond(client_ctx->dns_request, err);
    free(client_ctx);
}


void dns_service_client_ctx_discard(dns_client_ctx_t* client_ctx) {
    evdns_server_request_drop(client_ctx->dns_request);
    free(client_ctx);
}