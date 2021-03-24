//
// Created by lzf on 2021/2/20.
//
#include "boot.h"
#include "logger.h"
#include "service.h"
#include "direct_forward.h"
#include "server_forward.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <confuse.h>
#include <signal.h>

struct fs_ctx_s {
    struct event_base* event_base;
    service_ctx_t* service_ctx;
    direct_forward_ctx_t* direct_forward_ctx;
    server_ctx_t* server_ctx;
    dns_ctx_t* dns_ctx;

};

typedef struct fs_ctx_s fs_ctx_t;

/**
 * 读取日志模块配置
 * @param dest 配置结构体
 * @param config_location 配置文件所在目录
 */
static void read_logger_config(logger_config_t* dest, const char* config_location);

/**
 * 读取本地服务配置
 * @param dest 配置结构体
 * @param config_location 配置文件所在目录
 */
static void read_service_config(service_config_t* dest, const char* config_location);

/**
 * 读取代理服务器配置
 * @param dest 配置结构体
 * @param config_location 配置文件所在目录
 */
static void read_server_config(server_config_t* dest, const char* config_location);
static string_t* server_auth_argument_parse(char* username, char* password);

/**
 * 初始化PAC模块
 * @param config_location IP白名单文件所在目录
 * @param mode
 */
static void pac_module_initial(const char* config_location, int mode);

/**
 * 初始化各个模块并监听事件
 */
static void run_with_single_thread(service_config_t* service_config, server_config_t* server_config);

/**
 * SIGTERM信号处理函数
 */
static void sigterm_process_cb(int sig);

/**
 * Libevent日志信息回调函数
 */
static void event_log_callback_cb(int severity, const char *msg);

static fs_ctx_t fs_ctx = {0};

/**
 * 命令行参数为配置文件路径，默认当前目录
 */
int main(int argc, char** argv) {
    char* config_path;
    if (argc >= 2) {
        config_path = argv[1];
    } else {
        size_t len = strlen(argv[0]);
        int idx = -1;
        for (int i = 0; i < len; i++) {
            if (argv[0][i] == '/') {
                idx = i;
            }
        }

        if (idx == -1) {
            printf("Could not get default config path, program exit");
            return 1;
        }

        argv[0][idx] = '\0';
        config_path = argv[0];
    }

    // 初始化日志组件
    logger_config_t logger_config;
    read_logger_config(&logger_config, config_path);
    int res = logger_initial(&logger_config);
    if (res != 0) {
        printf("Logger initial failure\n");
        return 1;
    }
    string_free(logger_config.file_path);

    log_info("flyingsocks router client @ version: %s, build time: %s", FS_VERSION, FS_BUILD_TIME);

#ifdef DEBUG
    event_enable_debug_mode();
#endif

    // 设置libevent日志回调
    event_set_log_callback(event_log_callback_cb);

    // 初始化本地代理接口
    service_config_t service_config;
    read_service_config(&service_config, config_path);

    server_config_t server_config;
    read_server_config(&server_config, config_path);

    pac_module_initial(config_path, service_config.pac_mode);

    // 处理SIGTERM终止信号
    signal(SIGTERM, sigterm_process_cb);

    // 处理事件
    run_with_single_thread(&service_config, &server_config);

    log_info("program stop complete");
    return 0;
}

static void run_with_single_thread(service_config_t* service_config, server_config_t* server_config) {
    dns_config_t dns_config = {service_config->dns_port};
    struct event_base* evbase = event_base_new();

    service_ctx_t* service_ctx = proxy_service_init(service_config, evbase);
    direct_forward_ctx_t* direct_forward_ctx = direct_forward_init(service_ctx, evbase);
    dns_ctx_t* dns_ctx = dns_service_initial(&dns_config, evbase);
    server_ctx_t* server_ctx = server_forward_initial(server_config, service_ctx, dns_ctx, evbase);

    fs_ctx.event_base = evbase;
    fs_ctx.service_ctx = service_ctx;
    fs_ctx.direct_forward_ctx = direct_forward_ctx;
    fs_ctx.dns_ctx = dns_ctx;
    fs_ctx.server_ctx = server_ctx;

    log_info("Prepare to running event loop...");

    event_base_dispatch(evbase);
}

static void read_logger_config(logger_config_t* dest, const char* config_location) {
    string_t* path = string_new(config_location);
    if (string_get_last_char(path) != '/') {
        string_append_char(path, '/');
    }

    string_append(path, FS_CFG_LOGGER_NAME);

    FILE* file = fopen(string_get_content(path), "r");
    string_free(path);

    if (file == NULL) {
        dest->open_stdout = false;
        dest->level = FS_LOGGER_LEVEL_INFO;
        dest->file_path = string_new(FS_CFG_LOGGER_DEFAULT_PATH);
        return;
    }

    cfg_opt_t cfg_opt[] = {
            CFG_BOOL("enable-stdout", cfg_false, CFGF_NONE),
            CFG_STR("file-path", FS_CFG_LOGGER_DEFAULT_PATH, CFGF_NONE),
            CFG_STR("logger-level", FS_CFG_LOGGER_DEFAULT_LEVEL, CFGF_NONE),
            CFG_END()
    };

    cfg_t* cfg = cfg_init(cfg_opt, CFGF_NONE);
    cfg_parse_fp(cfg, file);

    dest->open_stdout = cfg_getbool(cfg, "enable-stdout") == cfg_true ? true : false;
    dest->file_path = string_new(cfg_getstr(cfg, "file-path"));
    char* level = cfg_getstr(cfg, "logger-level");
    if (strcmp(level, "ERROR") == 0) {
        dest->level = FS_LOGGER_LEVEL_ERROR;
    } else if (strcmp(level, "WARN") == 0) {
        dest->level = FS_LOGGER_LEVEL_WARN;
    } else if (strcmp(level, "INFO") == 0) {
        dest->level = FS_LOGGER_LEVEL_INFO;
    } else if (strcmp(level, "DEBUG") == 0) {
        dest->level = FS_LOGGER_LEVEL_DEBUG;
    } else if (strcmp(level, "TRACE") == 0){
        dest->level = FS_LOGGER_LEVEL_TRACE;
    } else {
        dest->level = FS_LOGGER_LEVEL_NONE;
    }

    cfg_free(cfg);
    fclose(file);
}


static void read_service_config(service_config_t* dest, const char* config_location) {
    string_t* path = string_new(config_location);
    if (string_get_last_char(path) != '/') {
        string_append_char(path, '/');
    }

    string_append(path, FS_CFG_SERVICE_NAME);

    FILE* file = fopen(string_get_content(path), "r");
    string_free(path);

    if (file == NULL) {
        log_warn("service.conf not found, using default config");
        dest->pac_mode = FS_PAC_MODE_IP_WHITELIST;
        dest->enable_tcp = true;
        dest->tcp_port = FS_CFG_SERVICE_DEFAULT_TCP_PORT;
        dest->enable_udp = false;
        dest->udp_port = FS_CFG_SERVICE_DEFAULT_UDP_PORT;
        return;
    }

    cfg_opt_t cfg_opt[] = {
            CFG_INT("proxy-auto-mode", 1, CFGF_NONE),
            CFG_BOOL("enable-tcp-proxy", cfg_true, CFGF_NONE),
            CFG_INT("proxy-tcp-port", FS_CFG_SERVICE_DEFAULT_TCP_PORT, CFGF_NONE),
            CFG_BOOL("enable-udp-proxy", cfg_false, CFGF_NONE),
            CFG_INT("proxy-udp-port", FS_CFG_SERVICE_DEFAULT_UDP_PORT, CFGF_NONE),
            CFG_INT("dns-service-port", FS_CFG_SERVICE_DEFAULT_DNS_PORT, CFGF_NONE),
            CFG_END()
    };

    cfg_t* cfg = cfg_init(cfg_opt, CFGF_NONE);
    cfg_parse_fp(cfg, file);

    dest->enable_tcp = cfg_getbool(cfg, "enable-tcp-proxy") == cfg_true ? true : false;
    dest->tcp_port = cfg_getint(cfg, "proxy-tcp-port");
    dest->enable_udp = cfg_getbool(cfg, "enable-udp-proxy") == cfg_true ? true : false;
    dest->udp_port = cfg_getint(cfg, "proxy-udp-port");
    dest->dns_port = cfg_getint(cfg, "dns-service-port");

    long pac_mode = cfg_getint(cfg, "proxy-auto-mode");
    if (pac_mode != FS_PAC_MODE_NO_PROXY && pac_mode != FS_PAC_MODE_IP_WHITELIST && pac_mode != FS_PAC_MODE_GLOBAL) {
        dest->pac_mode = FS_PAC_MODE_IP_WHITELIST;
    } else {
        dest->pac_mode = (int) pac_mode;
    }

    cfg_free(cfg);
    fclose(file);
}


static void read_server_config(server_config_t* dest, const char* config_location) {
    string_t* path = string_new(config_location);
    if (string_get_last_char(path) != '/') {
        string_append_char(path, '/');
    }

    string_append(path, FS_CFG_SERVER_NAME);

    FILE* file = fopen(string_get_content(path), "r");

    if (file == NULL) {
        log_error("server.conf NOT found, require location: %s", string_get_content(path));
        exit(FS_EXIT_SERVER_CONF_NOT_FOUND);
    }
    string_free(path);

    cfg_opt_t cfg_opt[] = {
           CFG_STR("hostname", "", CFGF_NONE),
           CFG_INT("port", 0, CFGF_NONE),
           CFG_STR("encrypt-type", "", CFGF_NONE),
           CFG_STR("auth-type", "", CFGF_NONE),
           CFG_STR_LIST("auth-arg", "", CFGF_LIST),
           CFG_END()
    };

    cfg_t* cfg = cfg_init(cfg_opt, CFGF_NONE);
    cfg_parse_fp(cfg, file);

    dest->hostname = strdup(cfg_getstr(cfg, "hostname"));
    dest->port = cfg_getint(cfg, "port");
    char* encrypt = cfg_getstr(cfg, "encrypt-type");
    if (strcmp(encrypt, "openssl") == 0) {
        dest->encrypt_type = ENCRYPT_TYPE_OPENSSL;
    } else if (strcmp(encrypt, "none") == 0) {
        dest->encrypt_type = ENCRYPT_TYPE_NONE;
    } else {
        log_error("Unknown encrypt type: %s", encrypt);
        exit(FS_EXIT_SERVER_CONF_ERROR);
    }

    char* auth = cfg_getstr(cfg, "auth-type");
    if (strcmp(auth, "simple") == 0) {
        dest->auth_type = AUTH_TYPE_SIMPLE;
    } else if (strcmp(auth, "user") == 0) {
        dest->auth_type = AUTH_TYPE_USER;
    } else {
        log_error("Unknown auth type: %s", encrypt);
        exit(FS_EXIT_SERVER_CONF_ERROR);
    }

    if (dest->auth_type == AUTH_TYPE_SIMPLE) {
        char* password = cfg_getnstr(cfg, "auth-arg", 0);
        if (password == NULL) {
            log_error("Could not found auth-arg config");
            exit(FS_EXIT_SERVER_CONF_ERROR);
        }
        dest->auth_argument = server_auth_argument_parse(NULL, password);
    } else if (dest->auth_type == AUTH_TYPE_USER) {
        char* user = cfg_getnstr(cfg, "auth-arg", 0);
        char* pass = cfg_getnstr(cfg, "auth-arg", 1);
        if (user == NULL || pass == NULL) {
            log_error("server.conf auth-arg config error");
            exit(FS_EXIT_SERVER_CONF_ERROR);
        }

        dest->auth_argument = server_auth_argument_parse(user, pass);
    }

    cfg_free(cfg);
    fclose(file);
}


static string_t* server_auth_argument_parse(char* username, char* password) {
    if (username == NULL && password == NULL) {
        return NULL;
    }

    char cache[1024];
    if (username == NULL) {
        sprintf(cache, "{\"password\":\"%s\"}", password);
    } else {
        sprintf(cache, "{\"user\":\"%s\",\"pass\":\"%s\"}", username, password);
    }

    char* cipher = base64_encode(cache);
    string_t* result = string_new(cipher);
    free(cipher);
    return result;
}

static void pac_module_initial(const char* config_location, int mode) {
    string_t* path = string_new(config_location);
    if (string_get_last_char(path) != '/') {
        string_append_char(path, '/');
    }

    string_append(path, FS_CFG_IP_WHITELIST);
    bool res = pac_initial(string_get_content(path), mode);
    if (!res) {
        log_error("PAC Module initial failure");
        exit(1);
    }
    string_free(path);
}


static void sigterm_process_cb(int sig) {
    if (sig != SIGINT) {
        return;
    }

    log_info("Prepare to stop program");
    proxy_service_stop(fs_ctx.service_ctx);
    direct_forward_stop(fs_ctx.direct_forward_ctx);
    dns_service_stop(fs_ctx.dns_ctx);
    server_forward_stop(fs_ctx.server_ctx);
    event_base_free(fs_ctx.event_base);
}

static void event_log_callback_cb(int severity, const char *msg) {
    switch (severity) {
        case EVENT_LOG_ERR: logger_error(msg); break;
        case EVENT_LOG_WARN: logger_warn(msg); break;
        case EVENT_LOG_MSG: logger_info(msg); break;
        case EVENT_LOG_DEBUG: logger_debug(msg); break;
        default:
            logger_trace(msg);
    }
}