//
// Created by lzf on 2021/2/21.
//
#include "service.h"
#include "logger.h"
#include "pac.h"
#include <stdlib.h>
#include <unistd.h>
#include <linux/netfilter_ipv4.h>

#ifndef FS_CLIENT_CTX_SUBSCRIBER_MAX
#define FS_CLIENT_CTX_SUBSCRIBER_MAX 5
#endif

#ifndef FS_SERVICE_DEFAULT_CLIENT_CTX_CLOSE_CALLBACK_SIZE
#define FS_SERVICE_DEFAULT_CLIENT_CTX_CLOSE_CALLBACK_SIZE 5
#endif

struct service_ctx_s {
    struct event_base* event_base;

    // PROTOCOL_TCP 本地代理服务套接字
    int tcp_socket_fd;

    // client_ctx订阅者
    struct client_ctx_subscriber {
        // 订阅者注册的回调函数
        client_ctx_publish_cb publish_cb;
        // 是否接收PAC判定为true的client_ctx
        bool accept_need_proxy;
        // 订阅者指定的回调参数
        void* cb_arg;
    } client_ctx_subscribers[FS_CLIENT_CTX_SUBSCRIBER_MAX];

    // 收集需要释放的client_ctx_s
    deque_t* garbage_queue;
};

struct client_ctx_s {
    // 所属的service_ctx_s
    service_ctx_t* service_ctx;

    // 目标服务器地址
    struct sockaddr_in target_server_addr;

    // 代理协议
    proxy_protocol_t protocol;

    // 是否需要通过代理服务器间接代理(由PAC判定)
    bool need_proxy;

    // 当前client_ctx_s是否被关闭(调用client_ctx_close函数)
    bool close;

    // 引用计数器
    int8_t refcnt;

    // 代理客户端Event
    struct bufferevent* event;

    // 当前client_ctx_s关闭时的回调，仅调用一次
    struct client_close_callback {
        client_close_callback_fn cb_fn;
        void* cb_arg;
    } close_callback_list[FS_SERVICE_DEFAULT_CLIENT_CTX_CLOSE_CALLBACK_SIZE];

    // 流量转发器
    msg_deliverer_t* msg_deliverer;
};

static int bind_tcp_port(uint16_t port, service_ctx_t* ctx);
static void tcp_accept_cb(int fd, short events, void* arg);
static void tcp_read_cb(struct bufferevent* event, void* arg);
static void tcp_event_cb(struct bufferevent* bevent, short event, void* arg);

static client_ctx_t* client_ctx_new(service_ctx_t* service_ctx, struct sockaddr_in* target, struct bufferevent* event,
                                    proxy_protocol_t protocol);

static void garbage_queue_clear_consumer(void* data, void* user_data);

service_ctx_t* proxy_service_init(service_config_t* config) {
    service_ctx_t* ctx = malloc(sizeof(service_ctx_t));
    ctx->event_base = NULL;
    ctx->tcp_socket_fd = -1;
    ctx->garbage_queue = deque_new(32);
    for (int i = 0; i < FS_CLIENT_CTX_SUBSCRIBER_MAX; i++) {
        (&ctx->client_ctx_subscribers[i])->publish_cb = NULL;
        (&ctx->client_ctx_subscribers[i])->cb_arg = NULL;
    }

    if (config->enable_tcp && bind_tcp_port(config->tcp_port, ctx) != 0) {
        free(ctx);
        return NULL;
    }

    struct event_base* event_base = event_base_new();
    ctx->event_base = event_base;
    if (event_base == NULL) {
        free(ctx);
        return NULL;
    }

    struct event* listen = event_new(event_base, ctx->tcp_socket_fd, EV_READ | EV_PERSIST, tcp_accept_cb, ctx);
    event_add(listen, NULL);
    return ctx;
}

void proxy_service_run(service_ctx_t* ctx) {
#ifdef FS_MULTITHREAD
    event_base_dispatch(ctx->event_base);
#else
    event_base_loop(ctx->event_base, EVLOOP_NONBLOCK);
    deque_t* garbage_queue = ctx->garbage_queue;
    deque_clear(garbage_queue, garbage_queue_clear_consumer, NULL);
#endif
}

int proxy_service_stop(service_ctx_t* ctx) {
    deque_free(ctx->garbage_queue, garbage_queue_clear_consumer, NULL);
    event_base_free(ctx->event_base);
    free(ctx);
    return 0;
}


static int bind_tcp_port(uint16_t port, service_ctx_t* ctx) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd == -1) {
        return 1;
    }

    int enable = 1;
    setsockopt(fd, SOL_IP, IP_TRANSPARENT, &enable, sizeof(enable)); // UDP: IP_RECVORIGDSTADDR

    struct sockaddr_in sin;
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(INADDR_ANY);
    sin.sin_port = htons(port);

    if (bind(fd, (const struct sockaddr *)&sin, sizeof(struct sockaddr_in)) < 0) {
        log_error("[bind_tcp_port] bind port %d failure", port);
        exit(FS_EXIT_TCP_BIND_FAILURE);
    }

    log_info("[bind_tcp_port] bind port %d success", port);

    if (listen(fd, FS_SERVICE_MAX_LISTEN_NUM) < 0) {
        log_error("[bind_tcp_port] listen port %d failure", port);
        exit(FS_EXIT_TCP_BIND_FAILURE);
    }

    log_info("[bind_tcp_port] listen port %d success", port);

    evutil_make_socket_nonblocking(fd);
    ctx->tcp_socket_fd = fd;
    return 0;
}


static void tcp_accept_cb(int fd, short events, void* arg) {
    struct sockaddr_in client;
    socklen_t len = sizeof(client);

    int client_fd = accept(fd, (struct sockaddr*)&client, &len);
    evutil_make_socket_nonblocking(client_fd);
#ifdef DEBUG
    log_trace("[service.c/tcp_accept_cb] Accept client FD:%d", client_fd);
#endif
    struct sockaddr_in target_addr;
    socklen_t socklen = sizeof(struct sockaddr_in);
    if (getsockopt(client_fd, SOL_IP, SO_ORIGINAL_DST, &target_addr, &socklen) != 0) {
        log_warn("[service.c/tcp_accept_cb] Could not get SO_ORIGINAL_DST, fd: %d", client_fd);
        close(client_fd);
        return;
    }

    service_ctx_t* ctx = (service_ctx_t*) arg;
    struct bufferevent* bev = bufferevent_socket_new(ctx->event_base, client_fd, BEV_OPT_CLOSE_ON_FREE);

    client_ctx_t* client_ctx = client_ctx_new(ctx, &target_addr, bev, PROTOCOL_TCP);
    if (client_ctx == NULL) {
        log_error("Could NOT create client_ctx");
        bufferevent_free(bev);
        return;
    }

    bufferevent_setcb(bev, tcp_read_cb, NULL, tcp_event_cb, client_ctx);
    bufferevent_enable(bev, EV_READ | EV_PERSIST);

    struct client_ctx_subscriber* subscribers = ctx->client_ctx_subscribers;
    bool publish = false;
    for (int i = 0; i < FS_CLIENT_CTX_SUBSCRIBER_MAX; i++) {
        struct client_ctx_subscriber* subscriber = &(subscribers[i]);
        if (subscriber->publish_cb != NULL && (subscriber->accept_need_proxy ^ client_ctx->need_proxy) == 0) {
            subscriber->publish_cb(client_ctx, subscriber->cb_arg);
            publish = true;
            break;
        }
    }

    client_ctx->refcnt++;
    if (!publish) {
        log_warn("[service.c/tcp_accept_cb] ClientContextSubscriber not found");
        client_ctx_free(client_ctx);
    }
}

static void garbage_queue_clear_consumer(void* data, void* user_data) {
    client_ctx_t* ctx = (client_ctx_t*) data;
    msg_deliver_cancel(ctx->msg_deliverer);
    msg_deliver_destroy(ctx->msg_deliverer);
    free(ctx);
}


static void tcp_read_cb(struct bufferevent* event, void* arg) {
    client_ctx_t* client_ctx = (client_ctx_t*) arg;

    byte_buf_t* buf = byte_buf_new(4096);
    int read_len = byte_buf_event_read(buf, event);
#ifdef DEBUG
    log_trace("[service.c/tcp_read_cb] Read message, capacity: %d", read_len);
#endif
    int res = msg_deliver_transfer(client_ctx->msg_deliverer, buf);
    byte_buf_release(buf);
    if (res != 0) {
        client_ctx_free(client_ctx);
    }
}

static void tcp_event_cb(struct bufferevent* bevent, short event, void* arg) {
    if (event & BEV_EVENT_EOF) {
        client_ctx_free(arg);
    } else if (event & BEV_EVENT_ERROR) {
        log_error("[service.c/tcp_event_cb] Event error");
        client_ctx_free(arg);
    }
}


bool client_ctx_put_close_callback(client_ctx_t* ctx, client_close_callback_fn callback_fn, void* cb_arg) {
    struct client_close_callback* cb_list = ctx->close_callback_list;
    for (int i = 0; i < FS_SERVICE_DEFAULT_CLIENT_CTX_CLOSE_CALLBACK_SIZE; i++) {
        struct client_close_callback* cb = &cb_list[i];
        if (cb->cb_fn == NULL) {
            cb->cb_fn = callback_fn;
            cb->cb_arg = cb_arg;
            return true;
        }
    }
    return false;
}


static client_ctx_t* client_ctx_new(service_ctx_t* service_ctx, struct sockaddr_in* target, struct bufferevent* event,
                                    proxy_protocol_t protocol) {
    client_ctx_t* ctx = malloc(sizeof(client_ctx_t));
    if (ctx == NULL) {
        return NULL;
    }

    msg_deliverer_t* deliverer = msg_deliver_new();
    if (deliverer == NULL) {
        free(ctx);
        return NULL;
    }

    ctx->service_ctx = service_ctx;
    ctx->event = event;
    ctx->protocol = protocol;

    struct sockaddr_in* target_addr = &(ctx->target_server_addr);
    ctx->close = false;
    ctx->refcnt = 1;
    target_addr->sin_family = target->sin_family;
    target_addr->sin_port = target->sin_port;
    target_addr->sin_addr.s_addr = target->sin_addr.s_addr;

    struct client_close_callback* cb_list = ctx->close_callback_list;
    for (int i = 0; i < FS_SERVICE_DEFAULT_CLIENT_CTX_CLOSE_CALLBACK_SIZE; i++) {
        struct client_close_callback* callback = &cb_list[i];
        callback->cb_arg = NULL;
        callback->cb_fn = NULL;
    }
    ctx->need_proxy = pac_need_proxy(target_addr->sin_addr.s_addr);
    ctx->msg_deliverer = deliverer;
    return ctx;
}

struct sockaddr_in* client_ctx_get_target_server_address(client_ctx_t* ctx) {
    return &ctx->target_server_addr;
}

void client_ctx_free(client_ctx_t* ctx) {
    int8_t refcnt = ctx->refcnt;
    if (refcnt <= 0) {
        log_error("Illegal refcnt: %d", refcnt);
        return;
    }

    ctx->refcnt = refcnt - 1;

    if (ctx->close) {
        return;
    }
    ctx->close = true;

    struct client_close_callback* cb_list = ctx->close_callback_list;
    for (int i = 0; i < FS_SERVICE_DEFAULT_CLIENT_CTX_CLOSE_CALLBACK_SIZE; i++) {
        struct client_close_callback* cb = &cb_list[i];
        if (cb->cb_fn != NULL) {
            cb->cb_fn(ctx, cb->cb_arg);
        }
    }

    bufferevent_free(ctx->event);
    if (ctx->refcnt == 0) {
        deque_offer_tail(ctx->service_ctx->garbage_queue, ctx);
    }
}


proxy_protocol_t client_ctx_get_proxy_protocol(client_ctx_t* ctx) {
    return ctx->protocol;
}

int client_ctx_write_data(client_ctx_t* ctx, byte_buf_t* buf) {
    if (ctx->close) {
        return -1;
    }
    int res = byte_buf_event_write(buf, ctx->event);
    if (res < 0) {
        log_error("[client_ctx_write_data] Could not write data, CODE: %d", res);
    }
    return res;
}

bool client_ctx_set_msg_receiver(client_ctx_t* ctx, msg_deliver_receiver_t* receiver) {
    int res = msg_deliver_set_receiver(ctx->msg_deliverer, receiver);
    if (res != 0) {
        log_error("[client_ctx_set_msg_receiver] Could not setup message receiver, CODE: %d", res);
    }

    return res == 0 ? true : false;
}


bool proxy_service_register_client_ctx_publish_cb(service_ctx_t* ctx, client_ctx_publish_cb publish_cb,
                                                  bool accept_need_proxy, void* arg) {
    struct client_ctx_subscriber* subscribers = ctx->client_ctx_subscribers;
    for (int i = 0; i < FS_CLIENT_CTX_SUBSCRIBER_MAX; i++) {
        struct client_ctx_subscriber* subscriber = &subscribers[i];
        if (subscriber->publish_cb == NULL) {
            subscriber->publish_cb = publish_cb;
            subscriber->accept_need_proxy = accept_need_proxy;
            subscriber->cb_arg = arg;
            return true;
        }
    }

    return false;
}