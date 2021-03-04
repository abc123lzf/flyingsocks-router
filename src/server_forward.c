//
// Created by lzf on 2021/2/26.
//

#include "service.h"
#include "server_forward.h"
#include "logger.h"
#include <stdlib.h>
#include <netdb.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <event2/bufferevent_ssl.h>
#include <assert.h>
#include <signal.h>

#ifndef FS_SERVER_MAX_TRANSACTION
#define FS_SERVER_MAX_TRANSACTION 8192
#endif

#ifndef FS_SERVER_MESSAGE_MAX_LEN
#define FS_SERVER_MESSAGE_MAX_LEN 20971520
#endif

#ifndef FS_SERVER_INPUT_CACHE_SIZE
#define FS_SERVER_INPUT_CACHE_SIZE 8192
#endif

#ifndef FS_SERVER_PROXY_MSG_CACHE_SIZE
#define FS_SERVER_PROXY_MSG_CACHE_SIZE 65536
#endif

#define FS_SERVER_AUTH_MSG_HEADER {0x6C, 0x7A, 0x66}
#define FS_SERVER_AUTH_MSG_HEADER_LEN 3
#define FS_SERVER_SVID_PROXY 0
#define FS_SERVER_SVID_PING 0x7F
#define FS_SERVER_SVID_PONG 0x7E

typedef struct auth_request_s auth_request_t;
typedef struct auth_response_s auth_response_t;
typedef struct proxy_request_s proxy_request_t;
typedef struct proxy_response_s proxy_response_t;
typedef struct ping_s ping_t;
typedef struct pong_s pong_t;

static bool server_connect(server_ctx_t* ctx);
static void client_ctx_accept_cb(client_ctx_t* client_ctx, void* arg);
static void client_ctx_close_cb(void* arg);
static void client_ctx_request_cb(byte_buf_t* buffer, void* arg);

struct client_ctx_cb_args_s {
    server_ctx_t* server_ctx;
    client_ctx_t* client_ctx;
    uint32_t tid;
};

static void read_cb(struct bufferevent* event, void* arg);
static void read_auth_response(struct bufferevent* event, server_ctx_t* ctx);
static bool read_proxy_stage_message(struct bufferevent* event, server_ctx_t* ctx);
static void process_proxy_response(server_ctx_t* ctx);
static void process_ping_message(server_ctx_t* ctx);

static void event_cb(struct bufferevent* bufferevent, short event, void* arg);
static void send_auth_request(server_ctx_t* ctx, struct bufferevent* bufferevent);

static bool submit_ping_task(server_ctx_t* ctx);


const static char auth_msg_header[] = FS_SERVER_AUTH_MSG_HEADER;

/*
 * 认证请求，头部字段固定，认证类型分为普通认证和用户认证
 * msg为认证参数，JSON编码
 * */
struct auth_request_s {
    char header[FS_SERVER_AUTH_MSG_HEADER_LEN];
    int8_t auth_type;
    uint16_t len;
    const char* msg;
};

/*
 * 认证响应
 * */
struct auth_response_s {
    char header[FS_SERVER_AUTH_MSG_HEADER_LEN];
    int8_t success;
    uint16_t len;
    char* extra_msg;
};

static void auth_response_decode(byte_buf_t* buffer, auth_response_t* dest, int* stage);

#define FS_SERVER_AUTH_RESP_HEADER_LEN (FS_SERVER_AUTH_MSG_HEADER_LEN * sizeof(int8_t) + sizeof(int8_t) + sizeof(uint16_t))
#define FS_SERVER_AUTH_RESP_DECODE_FINISH_STAGE 4

struct proxy_request_s {
    int8_t svid;
    uint32_t len;
    uint32_t tid;
    uint8_t hlen;
    char* host;
    uint8_t type;
    uint16_t port;
    uint32_t mlen;
    byte_buf_t* msg;
};

static void proxy_request_build(struct proxy_request_s* request, uint32_t tid, char* host, uint8_t type,
                                uint16_t port, byte_buf_t* msg);
static void proxy_request_transfer(struct bufferevent* event, proxy_request_t* request);

#define FS_SERVER_PROXY_REQ_TYPE_TCP 0
#define FS_SERVER_PROXY_REQ_TYPE_UDP 0x40
#define FS_SERVER_PROXY_REQ_TYPE_CLOSE 0x20

struct proxy_response_s {
    int8_t svid;
    uint32_t len;
    uint32_t tid;
    uint8_t status;
    uint32_t mlen;
    byte_buf_t* msg;
};

#define FS_SERVER_PROXY_RESP_DECODE_FINISH_STAGE 6

static void proxy_response_decode(byte_buf_t* buffer, proxy_response_t* response, uint64_t* stage, char* cache);

#define FS_SERVER_PING_CONTENT "PING"
struct ping_s {
    int8_t svid;
    uint32_t len;
    char content[sizeof(FS_SERVER_PING_CONTENT)];
};

#define FS_SERVER_PING_DECODE_FINISH_STAGE 3
static void ping_decode(byte_buf_t* buffer, ping_t* ping, uint64_t* stage);

#define FS_SERVER_PONG_CONTENT "PONG"
struct pong_s {
    int8_t svid;
    uint32_t len;
    char content[sizeof(FS_SERVER_PONG_CONTENT)];
};
#define FS_SERVER_PONG_DECODE_FINISH_STAGE 3
static void pong_decode(byte_buf_t* buffer, pong_t* pong, uint64_t* stage);

const static ping_t PING = {FS_SERVER_SVID_PING, 4, FS_SERVER_PING_CONTENT};
const static pong_t PONG = {FS_SERVER_SVID_PONG, 4, FS_SERVER_PONG_CONTENT};

static void proxy_stage_message_decode(byte_buf_t* buffer, proxy_response_t* response,
                                       ping_t* ping, pong_t* pong, uint64_t* stage, char* cache);

struct server_ctx_s {
    // 服务器配置
    server_config_t* config;

    // 本地代理服务上下文
    service_ctx_t* service_ctx;

    // event base
    struct event_base* event_base;

    // 与服务端连接产生的bufferevent
    struct bufferevent* event;

    // SSL通信组件
    struct ssl_st* ssl_st;

    // 下一个事务ID
    uint32_t next_tid;

    // 是否建立连接
    bool connect;

    // 是否通过服务端认证
    bool auth;

    // 事务ID与client上下文映射关系
    client_ctx_t* transactions[FS_SERVER_MAX_TRANSACTION];

    // 认证消息响应解码缓存
    auth_response_t auth_decode_cache;

    // 消息响应解码缓存步骤
    int auth_decode_stage;

    // 代理消息响应解码缓存
    proxy_response_t proxy_decode_cache;

    // 消息响应解码缓存步骤
    // 8位消息类型 + 32位已解码的消息长度 + 8位解码步骤
    uint64_t proxy_decode_stage;

    // PING消息解码缓存
    ping_t ping_cache;

    // PONG消息解码缓存
    pong_t pong_cache;

    // 代理阶段输入缓存
    char input_cache[FS_SERVER_INPUT_CACHE_SIZE];

    // 代理消息响应内容缓存
    char proxy_message_cache[FS_SERVER_PROXY_MSG_CACHE_SIZE];
};

static inline uint8_t stage_type(uint64_t stage) {
    return stage >> 56;
}

static inline uint8_t stage_step(uint64_t stage) {
    return stage & (uint8_t) 0xFF;
}

static inline uint32_t stage_decoded_length(uint64_t stage) {
    return (stage >> 8) & (uint64_t) 0x00000000FFFFFFFF;
}

static inline void stage_type_set(uint64_t* stage, uint8_t type) {
    uint64_t t = (uint64_t) type << 56;
    *stage &= (uint64_t) 0x00FFFFFFFFFFFFFF;
    *stage |= t;
}

static inline void stage_step_set(uint64_t* stage, uint8_t step) {
    uint64_t v = *stage;
    v &= (uint64_t) 0xFFFFFFFFFFFFFF00;
    v |= step;
    *stage = v;
}

static inline void stage_decoded_length_set(uint64_t* stage, uint32_t length) {
    uint64_t v = *stage;
    v &= (uint64_t) 0xFFFFFF00000000FF;
    v = v | ((uint64_t) length << 8);
    *stage = v;
}

static inline void auth_decode_cache_clean(auth_response_t* cache) {
    if (cache->extra_msg != NULL) {
        free(cache->extra_msg);
    }
    memset(cache, 0, sizeof(struct auth_response_s));
}

static inline void proxy_decode_cache_clean(proxy_response_t* cache) {
    if (cache->msg != NULL) {
        byte_buf_release(cache->msg);
    }
    memset(cache, 0, sizeof(struct proxy_response_s));
}


server_ctx_t* server_forward_initial(server_config_t *config, service_ctx_t* service_ctx) {
    if (config == NULL || service_ctx == NULL) {
        return NULL;
    }

    server_ctx_t* ctx = calloc(sizeof(server_ctx_t), 1);
    if (ctx == NULL) {
        return NULL;
    }

    ctx->config = config;
    ctx->service_ctx = service_ctx;
    struct event_base* base = event_base_new();
    if (base == NULL) {
        free(ctx);
        return NULL;
    }

    ctx->event_base = base;

    if (!server_connect(ctx)) {
        free(ctx);
        return NULL;
    }

    submit_ping_task(ctx);
    return ctx;
}


static struct ssl_st* ssl_st_create() {
    static SSL_CTX* ctx = NULL;
    if (ctx == NULL) {
        SSL_library_init();
        OpenSSL_add_all_algorithms();
        ERR_load_crypto_strings();
        SSL_load_error_strings();
        ctx = SSL_CTX_new(TLSv1_2_client_method());
        if (ctx == NULL) {
            log_error("TLS v1.2 Not support.");
            exit(FS_EXIT_SSL_NOT_SUPPORT);
        }
    }

    return SSL_new(ctx);
}


void server_forward_run(server_ctx_t *ctx) {
    event_base_loop(ctx->event_base, EVLOOP_NONBLOCK);
}

void server_forward_stop(server_ctx_t *ctx) {
    bufferevent_free(ctx->event);
    auth_decode_cache_clean(&ctx->auth_decode_cache);
    proxy_decode_cache_clean(&ctx->proxy_decode_cache);
    event_base_free(ctx->event_base);
    free(ctx);
}

static bool server_connect(server_ctx_t* ctx) {
    const server_config_t* config = ctx->config;
    char* hostname = config->hostname;
    uint16_t port = config->port;

    if (ctx->ssl_st != NULL) {
        SSL_free(ctx->ssl_st);
        ctx->ssl_st = NULL;
    }

    struct bufferevent* event = NULL;
    if (config->encrypt_type == ENCRYPT_TYPE_OPENSSL) {
        ctx->ssl_st = ssl_st_create();
        event = bufferevent_openssl_socket_new(ctx->event_base, -1, ctx->ssl_st, BUFFEREVENT_SSL_CONNECTING, BEV_OPT_CLOSE_ON_FREE);
    } else {
        event = bufferevent_socket_new(ctx->event_base, -1, BEV_OPT_CLOSE_ON_FREE);
    }

    if (event == NULL) {
        return false;
    }

    ctx->connect = false;
    ctx->auth = false;
    ctx->event = event;
    ctx->next_tid = 0;
    for (int i = 0; i < FS_SERVER_MAX_TRANSACTION; i++) {
        client_ctx_t* client_ctx = ctx->transactions[i];
        if (client_ctx != NULL) {
            client_ctx_free(client_ctx);
        }
    }

    ctx->auth_decode_stage = 0;
    auth_decode_cache_clean(&ctx->auth_decode_cache);
    ctx->proxy_decode_stage = 0;
    proxy_decode_cache_clean(&ctx->proxy_decode_cache);

    int res = bufferevent_socket_connect_hostname(event, NULL, AF_UNSPEC, hostname, port);
    if (res != 0) {
        return false;
    }

    log_info("Connect to proxy server %s:%d ...", hostname, port);

    bufferevent_setcb(event, read_cb, NULL, event_cb, ctx);
    res = bufferevent_enable(event, EV_READ | EV_PERSIST);
    if (res != 0) {
        log_warn("Could not enable bufferevent");
    }

    return true;
}

static void client_ctx_accept_cb(client_ctx_t* client_ctx, void* arg) {
    server_ctx_t* server_ctx = (server_ctx_t*) arg;
    if (server_ctx->event == NULL) {
        client_ctx_free(client_ctx);
        return;
    }

    struct client_ctx_cb_args_s* user_args = malloc(sizeof(struct client_ctx_cb_args_s));
    user_args->server_ctx = server_ctx;
    user_args->client_ctx = client_ctx;

    msg_deliver_receiver_t* receiver = msg_deliver_receiver_new(client_ctx_request_cb, client_ctx_close_cb, user_args);
    uint32_t tid = server_ctx->next_tid;
    assert(tid < FS_SERVER_MAX_TRANSACTION);

    bool allocate = false;
    for (int i = tid, c = 0; c < FS_SERVER_MAX_TRANSACTION; i++, c++) {
        if (server_ctx->transactions[i] == NULL) {
            server_ctx->transactions[i] = client_ctx;
            tid = i;
            allocate = true;
            break;
        }

        if (i == FS_SERVER_MAX_TRANSACTION - 1) {
            i = 0;
        }
    }

    if (!allocate) {
        log_error("Could not allocate transaction");
        free(user_args);
        free(receiver);
        client_ctx_free(client_ctx);
        return;
    }

    user_args->tid = tid;
    server_ctx->next_tid = tid != FS_SERVER_MAX_TRANSACTION - 1 ? tid + 1 : 0;
    client_ctx_set_msg_receiver(client_ctx, receiver);
}

static void client_ctx_request_cb(byte_buf_t* buffer, void* arg) {
    struct client_ctx_cb_args_s* user_args = (struct client_ctx_cb_args_s*) arg;
    server_ctx_t* ctx = user_args->server_ctx;
    uint32_t tid = user_args->tid;

    if (ctx->transactions[tid] == NULL || !ctx->connect) {
        client_ctx_free(user_args->client_ctx);
        byte_buf_release(buffer);
        return;
    }

    client_ctx_t* client_ctx = user_args->client_ctx;

    struct sockaddr_in* target_addr = client_ctx_get_target_server_address(client_ctx);
    char* host = inet_ntoa(target_addr->sin_addr);
    proxy_protocol_t protocol = client_ctx_get_proxy_protocol(client_ctx);

    struct proxy_request_s request;
    proxy_request_build(&request, tid, host, protocol == PROTOCOL_TCP ? FS_SERVER_PROXY_REQ_TYPE_TCP : FS_SERVER_PROXY_REQ_TYPE_UDP,
                        ntohs(target_addr->sin_port), buffer);
    proxy_request_transfer(ctx->event, &request);
    byte_buf_release(buffer);
}


static void client_ctx_close_cb(void* arg) {
    struct client_ctx_cb_args_s* user_args = (struct client_ctx_cb_args_s*) arg;
    server_ctx_t* ctx = user_args->server_ctx;
    uint32_t tid = user_args->tid;

    client_ctx_t* client_ctx = ctx->transactions[tid];
    if (client_ctx == NULL) {
        goto finally;
    }

    if (!ctx->connect) {
        goto finally;
    }

    struct sockaddr_in* target_addr = client_ctx_get_target_server_address(client_ctx);
    char* host = inet_ntoa(target_addr->sin_addr);

    struct bufferevent* event = ctx->event;

    struct proxy_request_s close_request;
    proxy_request_build(&close_request, tid, host, FS_SERVER_PROXY_REQ_TYPE_CLOSE, ntohs(target_addr->sin_port),NULL);
    proxy_request_transfer(event, &close_request);

finally:
    ctx->transactions[tid] = NULL;
    free(user_args);
}


static void read_cb(struct bufferevent* event, void* arg) {
    server_ctx_t* ctx = (server_ctx_t*) arg;
    if (!ctx->auth) {
        log_info("Decode auth response from remote server %s:%d", ctx->config->hostname, ctx->config->port);
        read_auth_response(event, ctx);
        if (ctx->auth) {
            log_info("Proxy server auth success");
            proxy_service_register_client_ctx_publish_cb(ctx->service_ctx, client_ctx_accept_cb, true, ctx);
        }
        return;
    }

    bool res = true;
    while (res) {
        res = read_proxy_stage_message(event, ctx);
    }
}


static void read_auth_response(struct bufferevent* event, server_ctx_t* ctx) {
    int* stage = &ctx->auth_decode_stage;
    size_t readable = evbuffer_get_length(bufferevent_get_input(event));

    if (*stage == 0 && readable < FS_SERVER_AUTH_RESP_HEADER_LEN) {
        return;
    } else if (*stage == 3 && readable < (&ctx->auth_decode_cache)->len) {
        return;
    }

    if (*stage == 0) {
        byte_buf_t* header = byte_buf_wrap(ctx->input_cache, FS_SERVER_AUTH_RESP_HEADER_LEN);
        byte_buf_event_read(header, event);
        auth_response_decode(header, &ctx->auth_decode_cache, stage);
        if (*stage == 3) {
            byte_buf_release(header);
            return;
        } else if (*stage == FS_SERVER_AUTH_RESP_DECODE_FINISH_STAGE) {
            byte_buf_release(header);
        } else {
            exit(FS_EXIT_AUTH_MSG_DECODE_ERROR);
        }
    } else if (*stage == 3) {
        auth_response_t* result = &ctx->auth_decode_cache;
        byte_buf_t* body = byte_buf_wrap(ctx->input_cache, result->len);
        byte_buf_event_read(body, event);
        auth_response_decode(body, &ctx->auth_decode_cache, stage);
        byte_buf_release(body);
    }

    if (*stage == FS_SERVER_AUTH_RESP_DECODE_FINISH_STAGE) {
        auth_response_t *result = &ctx->auth_decode_cache;
        if (!result->success) {
            log_error("Remote server authentication failure");
            exit(FS_EXIT_AUTH_FAILURE);
        } else {
            ctx->auth = true;
        }
    } else if (*stage == -1) {
        exit(FS_EXIT_AUTH_MSG_DECODE_ERROR);
    }
}


static bool read_proxy_stage_message(struct bufferevent* event, server_ctx_t* ctx) {
    size_t readable = evbuffer_get_length(bufferevent_get_input(event));
    if (readable == 0) {
        return false;
    }

    // 构造静态缓冲区
    byte_buf_t* buffer = byte_buf_wrap(ctx->input_cache,readable > FS_SERVER_INPUT_CACHE_SIZE ?
                                        FS_SERVER_INPUT_CACHE_SIZE : readable);
    byte_buf_event_read(buffer, event);

    while (byte_buf_readable_bytes(buffer) > 0) {
        // 解码PING、PONG以及代理响应
        uint64_t* stage = &ctx->proxy_decode_stage;
        proxy_stage_message_decode(buffer, &ctx->proxy_decode_cache, &ctx->ping_cache, &ctx->pong_cache, stage, ctx->proxy_message_cache);

        // 分析解码类型和解码进度
        uint8_t type = stage_type(*stage);
        uint8_t step = stage_step(*stage);

        if (type == FS_SERVER_SVID_PROXY && step == FS_SERVER_PROXY_RESP_DECODE_FINISH_STAGE) {
            process_proxy_response(ctx);
            *stage = 0;
            memset(&ctx->proxy_decode_cache, 0, sizeof(struct proxy_response_s));
        } else if (type == FS_SERVER_SVID_PING && step == FS_SERVER_PING_DECODE_FINISH_STAGE) {
            process_ping_message(ctx);
            *stage = 0;
            memset(&ctx->ping_cache, 0, sizeof(struct ping_s));
        } else if (type == FS_SERVER_SVID_PONG && step == FS_SERVER_PONG_DECODE_FINISH_STAGE) {
            *stage = 0;
            memset(&ctx->pong_cache, 0, sizeof(struct pong_s));
        }
    }
    byte_buf_release(buffer);
    return readable > FS_SERVER_INPUT_CACHE_SIZE ? true : false;
}


static void process_proxy_response(server_ctx_t* ctx) {
    proxy_response_t* response = &ctx->proxy_decode_cache;
    uint32_t tid = response->tid;
    if (tid > FS_SERVER_MAX_TRANSACTION) {
        log_error("Proxy response transaction id out of bounds, value: %d", tid);
        goto release_body;
    }

    client_ctx_t* client_ctx = ctx->transactions[tid];
    if (client_ctx == NULL) {
        log_warn("Can not found transaction id in array, tid: %d", tid);
        goto release_body;
    }

    if (response->status == 0) {
        client_ctx_write_data(client_ctx, response->msg);
    } else {
        client_ctx_free(client_ctx);
    }
release_body:
    byte_buf_release(response->msg);
}


static void process_ping_message(server_ctx_t* ctx) {
    struct bufferevent* event = ctx->event;

    byte_buf_t* buffer = byte_buf_new(sizeof(struct pong_s) - 1);
    byte_buf_write_char(buffer, PONG.svid);
    byte_buf_write_int(buffer, PONG.len);
    byte_buf_write_string(buffer, PONG.content, sizeof(PONG.content) - 1);

    byte_buf_event_write(buffer, event);
    byte_buf_release(buffer);
}


static void event_cb(struct bufferevent* bufferevent, short event, void* arg) {
    server_ctx_t* ctx = (server_ctx_t*) arg;
    if (event & BEV_EVENT_CONNECTED) {
        log_info("Success connect to proxy server");
        ctx->connect = true;
        send_auth_request(ctx, bufferevent);
        return;
    }

    // 断线重连
    if (event & (BEV_EVENT_EOF | BEV_EVENT_ERROR)) {
        ctx->connect = false;
        ctx->auth = false;
        log_warn("Proxy server connection error, ERROR CODE: %s", evutil_socket_error_to_string(EVUTIL_SOCKET_ERROR()));
        bufferevent_free(bufferevent);
        server_connect(ctx);
        return;
    }

    if (event & BEV_EVENT_EOF) {
        ctx->connect = false;
        ctx->auth = false;
        bufferevent_free(bufferevent);
        ctx->event = NULL;
        raise(SIGTERM);
    } else if (event & BEV_EVENT_TIMEOUT) {
        ctx->connect = false;
        ctx->auth = false;
        bufferevent_free(bufferevent);
        ctx->event = NULL;
        log_warn("Connect to proxy server timeout, ready to reconnect");
        server_connect(ctx);
    }
}


static inline void send_auth_request(server_ctx_t* ctx, struct bufferevent* bufferevent) {
    server_config_t* config = ctx->config;
    auth_request_t request;
    for (int i = 0; i < FS_SERVER_AUTH_MSG_HEADER_LEN; i++) {
        request.header[i] = auth_msg_header[i];
    }
    request.auth_type = config->auth_type;
    request.len = string_length(config->auth_argument);
    request.msg = string_get_content(config->auth_argument);

    size_t size = sizeof(request.header) + sizeof(request.auth_type) + sizeof(request.len) + request.len;
    byte_buf_t* buffer = byte_buf_new(size);

    byte_buf_write_string(buffer, request.header, FS_SERVER_AUTH_MSG_HEADER_LEN);
    byte_buf_write_byte(buffer, request.auth_type);
    byte_buf_write_ushort(buffer, request.len);
    byte_buf_write_string(buffer, request.msg, request.len);

    log_info("Send auth message to remote proxy server %s:%d", ctx->config->hostname, ctx->config->port);
    byte_buf_event_write(buffer, bufferevent);
    free(buffer);
}


static void auth_response_decode(byte_buf_t* buffer, auth_response_t* dest, int* stage) {
    if (*stage > 3) {
        *stage = 0;
    }

    if (*stage == 0) {
        bool res = byte_buf_read_string(buffer, dest->header, FS_SERVER_AUTH_MSG_HEADER_LEN);
        if (!res) {
            return;
        }

        const static char correct_header[] = FS_SERVER_AUTH_MSG_HEADER;
        for (int i = 0; i < FS_SERVER_AUTH_MSG_HEADER_LEN; i++) {
            if (correct_header[i] != dest->header[i]) {
                (*stage) = -1;
                return;
            }
        }

        (*stage)++;
    }

    if (*stage == 1) {
        uint8_t success;
        bool res = byte_buf_read_byte(buffer, &success);
        if (!res) {
            return;
        }
        dest->success = success != 0 ? true : false;
        (*stage)++;
    }

    if (*stage == 2) {
        uint16_t msglen;
        bool res = byte_buf_read_ushort(buffer, &msglen);
        if (!res) {
            return;
        }

        dest->len = msglen;
        (*stage)++;
    }

    if (*stage == 3) {
        uint16_t msglen = dest->len;
        if (msglen == 0) {
            (*stage)++;
            return;
        }
        int32_t readable = byte_buf_readable_bytes(buffer);
        if (readable < msglen) {
            return;
        }
        char* msg = calloc(msglen + 1, 1);
        byte_buf_read_string(buffer, msg, msglen);
        dest->extra_msg = msg;
        (*stage)++;
    }
}


static inline void proxy_stage_message_decode(byte_buf_t* buffer, proxy_response_t* response,
                                       ping_t* ping, pong_t* pong, uint64_t* stage, char* cache) {
    uint8_t step = stage_step(*stage);
    if (step == 0) {
        // 提取服务ID，设置stage的type位为服务ID
        uint8_t svid = -1;
        byte_buf_read_byte(buffer, &svid);

        if (svid == FS_SERVER_SVID_PROXY) {
            response->svid = FS_SERVER_SVID_PROXY;
        } else if (svid == FS_SERVER_SVID_PING) {
            ping->svid = FS_SERVER_SVID_PING;
        } else if (svid == FS_SERVER_SVID_PONG) {
            pong->svid = FS_SERVER_SVID_PONG;
        } else {
            assert(0);
        }

        stage_type_set(stage, svid);
        stage_step_set(stage, 1);
    }

    uint8_t type = stage_type(*stage);
    if (type == FS_SERVER_SVID_PROXY) {
        proxy_response_decode(buffer, response, stage, cache);
    } else if (type == FS_SERVER_SVID_PING) {
        ping_decode(buffer, ping, stage);
    } else if (type == FS_SERVER_SVID_PONG) {
        pong_decode(buffer, pong, stage);
    } else {
        assert(0);
    }
}


static inline bool proxy_message_decode_uint32(byte_buf_t* buffer, uint32_t* dest, uint64_t* stage) {
    int32_t readable = byte_buf_readable_bytes(buffer);
    int32_t hasread = stage_decoded_length(*stage);
    void* addr = (void*) dest;
    if (hasread + readable >= 4) {
        byte_buf_read_bytes(buffer, addr + hasread, 4 - hasread);
        *dest = ntohl(*dest);
        stage_decoded_length_set(stage, 4);
        return true;
    } else {
        byte_buf_read_bytes(buffer, addr + hasread, readable);
        stage_decoded_length_set(stage, hasread + readable);
        return false;
    }
}


static inline bool proxy_message_decode_msg(byte_buf_t* buffer, byte_buf_t* dest, uint64_t* stage, uint32_t mlen) {
    int32_t readable = byte_buf_readable_bytes(buffer);
    int32_t hasread = stage_decoded_length(*stage);
    if (hasread + readable >= mlen) {
        bool res = byte_buf_transfer(buffer, dest, (int32_t) mlen - hasread);
        assert(res);
        stage_decoded_length_set(stage, mlen);
        return true;
    } else {
        bool res = byte_buf_transfer(buffer, dest, readable);
        assert(res);
        stage_decoded_length_set(stage, hasread + readable);
        assert(byte_buf_readable_bytes(dest) == hasread + readable);
        return false;
    }
}

static inline bool proxy_message_decode_string(byte_buf_t* buffer, char* dest, uint64_t* stage, uint32_t mlen) {
    int32_t readable = byte_buf_readable_bytes(buffer);
    int32_t hasread = stage_decoded_length(*stage);
    if (hasread + readable >= mlen) {
        bool res = byte_buf_read_string(buffer, dest, (int32_t) mlen - hasread);
        assert(res);
        stage_decoded_length_set(stage, mlen);
        return true;
    } else {
        byte_buf_read_string(buffer, dest + hasread, readable);
        stage_decoded_length_set(stage, hasread + readable);
        return false;
    }
}


static inline void proxy_response_decode(byte_buf_t* buffer, proxy_response_t* response, uint64_t* stage, char* cache) {
    uint8_t step = stage_step(*stage);
    if (step == 1) {
        bool res = proxy_message_decode_uint32(buffer, &response->len, stage);
        if (!res) {
            return;
        }

        if (response->len > FS_SERVER_MESSAGE_MAX_LEN) {
            log_error("Proxy response message decode error: frame too large, size: %d", response->len);
            exit(FS_EXIT_PROXY_MSG_TOO_LARGE);
        }

        stage_decoded_length_set(stage, 0);
        stage_step_set(stage, ++step);
    }

    if (step == 2) {
        bool res = proxy_message_decode_uint32(buffer, &response->tid, stage);
        if (!res) {
            return;
        }

        stage_decoded_length_set(stage, 0);
        stage_step_set(stage, ++step);
    }

    if (step == 3) {
        uint8_t status;
        bool res = byte_buf_read_byte(buffer, &status);
        if (!res) {
            return;
        }
        response->status = status;
        stage_step_set(stage, ++step);
    }

    if (step == 4) {
        bool res = proxy_message_decode_uint32(buffer, &response->mlen, stage);
        if (!res) {
            return;
        }
        stage_decoded_length_set(stage, 0);
        stage_step_set(stage, ++step);
    }

    if (step == 5) {
        uint32_t mlen = response->mlen;
        assert(response->len == mlen + 1 + 4 + 4);
        if (response->msg == NULL) {
            response->msg = mlen <= FS_SERVER_PROXY_MSG_CACHE_SIZE ? byte_buf_wrap(cache, mlen) : byte_buf_new(mlen);
        }

        bool res = proxy_message_decode_msg(buffer, response->msg, stage, mlen);
        if (!res) {
            return;
        }
        stage_decoded_length_set(stage, 0);
        stage_step_set(stage, ++step);
    }
}


static void ping_decode(byte_buf_t* buffer, ping_t* ping, uint64_t* stage) {
    uint8_t step = stage_step(*stage);
    if (step == 1) {
        bool res = proxy_message_decode_uint32(buffer, &ping->len, stage);
        if (!res) {
            return;
        }

        // 复位解码长度
        stage_decoded_length_set(stage, 0);
        assert(ping->len == strlen(FS_SERVER_PING_CONTENT));
        stage_step_set(stage, ++step);
    }

    if (step == 2) {
        bool res = proxy_message_decode_string(buffer, ping->content, stage, ping->len);
        if (!res) {
            return;
        }

        // 复位解码长度
        stage_decoded_length_set(stage, 0);
        assert(strcmp(ping->content, FS_SERVER_PING_CONTENT) == 0);
        stage_step_set(stage, ++step);
    }
}

static void pong_decode(byte_buf_t* buffer, pong_t* pong, uint64_t* stage) {
    uint8_t step = stage_step(*stage);
    if (step == 1) {
        bool res = proxy_message_decode_uint32(buffer, &pong->len, stage);
        if (!res) {
            return;
        }
        stage_decoded_length_set(stage, 0);
        assert(pong->len == strlen(FS_SERVER_PONG_CONTENT));
        stage_step_set(stage, ++step);
    }

    if (step == 2) {
        bool res = proxy_message_decode_string(buffer, pong->content, stage, pong->len);
        if (!res) {
            return;
        }
        stage_decoded_length_set(stage, 0);
        assert(strcmp(pong->content, FS_SERVER_PONG_CONTENT) == 0);
        stage_step_set(stage, ++step);
    }
}

static inline void proxy_request_build(struct proxy_request_s* request, uint32_t tid, char* host, uint8_t type,
                                uint16_t port, byte_buf_t* msg) {
    request->svid = FS_SERVER_SVID_PROXY;
    request->tid = tid;
    request->host = host;
    request->type = type;
    request->port = port;
    request->msg = msg;
    request->hlen = strlen(host);
    request->mlen = msg != NULL ? byte_buf_readable_bytes(msg) : 0;
    request->len = sizeof(uint32_t) + sizeof(uint8_t) + request->hlen + sizeof(uint8_t) + sizeof(uint16_t) +
                   sizeof(uint32_t) + request->mlen;
}


static void proxy_request_transfer(struct bufferevent* event, proxy_request_t* request) {
    byte_buf_t* header = byte_buf_new(1 + 4 + 4 + 1 + request->hlen + 1 + 2 + 4);
    byte_buf_write_byte(header, request->svid);
    byte_buf_write_int(header, request->len);
    byte_buf_write_int(header, request->tid);
    byte_buf_write_byte(header, request->hlen);
    byte_buf_write_string(header, (const char*) request->host, request->hlen);
    byte_buf_write_byte(header, request->type);
    byte_buf_write_ushort(header, request->port);
    byte_buf_write_int(header, request->mlen);

    byte_buf_event_write(header, event);
    if (request->mlen > 0) {
        byte_buf_event_write(request->msg, event);
    }

    byte_buf_release(header);
}

static void ping_task(evutil_socket_t fd, short event, void* arg) {
    server_ctx_t* ctx = (server_ctx_t*) arg;
    if (!ctx->connect || !ctx->auth || ctx->event == NULL) {
        return;
    }

    byte_buf_t* buffer = byte_buf_new(sizeof(struct ping_s) - 1);
    byte_buf_write_char(buffer, PING.svid);
    byte_buf_write_int(buffer, PING.len);
    byte_buf_write_string(buffer, PING.content, sizeof(PING.content) - 1);
    byte_buf_event_write(buffer, ctx->event);
    byte_buf_release(buffer);
}

static bool submit_ping_task(server_ctx_t* ctx) {
    struct event_base* base = ctx->event_base;
    struct event* event = event_new(base, -1, EV_PERSIST, ping_task, ctx);
    if (event == NULL) {
        return false;
    }

    struct timeval timeout;
    timeout.tv_sec = 15;
    timeout.tv_usec = 0;
    int res = event_add(event, &timeout);
    if (res != 0) {
        return false;
    }
    return true;
}