//
// Created by lzf on 2021/2/21.
//

#include "buffer.h"
#include "logger.h"
#include "direct_forward.h"
#include <stdlib.h>
#include <unistd.h>

struct direct_forward_ctx_s {
    struct event_base* event_base;
};

static void client_ctx_accept_cb(client_ctx_t* client_ctx, void* arg);
static void tcp_read_cb(struct bufferevent* bevent, void* arg);
static void tcp_event_cb(struct bufferevent* bevent, short event, void* arg);
static void tcp_msg_receive_cb(byte_buf_t* buf, void* arg);
static void client_ctx_close_cb(client_ctx_t* client_ctx, void* arg);

direct_forward_ctx_t* direct_forward_init(service_ctx_t* service_ctx) {
    direct_forward_ctx_t* ctx = malloc(sizeof(direct_forward_ctx_t));
    if (ctx == NULL) {
        return NULL;
    }

    struct event_base* base = event_base_new();
    if (base == NULL) {
        free(ctx);
        return NULL;
    }

    ctx->event_base = base;

    proxy_service_register_client_ctx_publish_cb(service_ctx, client_ctx_accept_cb, false, ctx);
    return ctx;
}

void direct_forward_run(direct_forward_ctx_t* ctx) {
    event_base_loop(ctx->event_base, EVLOOP_NONBLOCK);
}

void direct_forward_stop(direct_forward_ctx_t* ctx) {
    event_base_free(ctx->event_base);
    free(ctx);
}


static void client_ctx_accept_cb(client_ctx_t* client_ctx, void* arg) {
    direct_forward_ctx_t* ctx = (direct_forward_ctx_t*) arg;

    if (client_ctx_get_proxy_protocol(client_ctx) == TCP) {
        struct bufferevent* event = bufferevent_socket_new(ctx->event_base, -1, BEV_OPT_CLOSE_ON_FREE);
        struct sockaddr_in* target_addr = client_ctx_get_target_server_address(client_ctx);

        int res = bufferevent_socket_connect(event, (const struct sockaddr *) target_addr, sizeof(struct sockaddr_in));
        if (res != 0) {
            log_warn("[direct_forward.c/client_ctx_accept_cb] Could not connect to target");
            client_ctx_free(client_ctx);
            return;
        }

#ifdef DEBUG
        int fd = bufferevent_getfd(event);
        struct sockaddr_in local_addr;
        socklen_t capacity = sizeof(struct sockaddr_in);
        getsockname(fd, (struct sockaddr *) &local_addr, &capacity);
#endif
        bufferevent_setcb(event, tcp_read_cb, NULL, tcp_event_cb, client_ctx);
        res = bufferevent_enable(event, EV_READ | EV_PERSIST);
        if (res != 0) {
            log_warn("[direct_forward.c/client_ctx_accept_cb] Could not enable bufferevent");
            client_ctx_free(client_ctx);
            return;
        }

        client_ctx_put_close_callback(client_ctx, client_ctx_close_cb, event);
    }

}


static void client_ctx_close_cb(client_ctx_t* client_ctx, void* arg) {
    bufferevent_free(arg);
}


static void tcp_read_cb(struct bufferevent* bevent, void* arg) {
    client_ctx_t* client_ctx = (client_ctx_t*) arg;

    byte_buf_t* buf = byte_buf_new(4096);
    byte_buf_event_read(buf, bevent);
    client_ctx_write_data(client_ctx, buf);
    byte_buf_release(buf);
}

static void tcp_event_cb(struct bufferevent* bevent, short event, void* arg) {
    client_ctx_t* client_ctx = (client_ctx_t*) arg;
    if (event & BEV_EVENT_EOF) {
        client_ctx_free(client_ctx);
        return;
    } else if (event & BEV_EVENT_ERROR) {
        log_error("[direct_forward.c/tcp_event_cb] tcp_event_cb");
        client_ctx_free(client_ctx);
    } else if (event & BEV_EVENT_TIMEOUT) {
        log_warn("[direct_forward.c/tcp_event_cb] Connect to %d timeout.", client_ctx_get_target_server_address(client_ctx)->sin_addr.s_addr);
        client_ctx_free(client_ctx);
    } else if (event & BEV_EVENT_CONNECTED) {
        msg_deliver_receiver_t* receiver = msg_deliver_receiver_new(tcp_msg_receive_cb, NULL, bevent);
        if (receiver == NULL) {
            log_error("[direct_forward.c/tcp_event_cb] Could not create MessageDeliverReceiver");
            client_ctx_free(client_ctx);
            return;
        }

        bool res = client_ctx_set_msg_receiver(client_ctx, receiver);
        if (!res) {
            log_error("[direct_forward.c/tcp_event_cb] Could not setup MessageDeliverReceiver");
            client_ctx_free(client_ctx);
            return;
        }
    }
}

static void tcp_msg_receive_cb(byte_buf_t* buf, void* arg) {
    byte_buf_event_write(buf, (struct bufferevent*) arg);
    byte_buf_release(buf);
}