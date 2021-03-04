//
// Created by lzf on 2021/2/21.
//

#ifndef FS_PAC_H
#define FS_PAC_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>
#include <stdint.h>
#include <arpa/inet.h>


#define FS_PAC_MODE_NO_PROXY 0
#define FS_PAC_MODE_IP_WHITELIST 1
#define FS_PAC_MODE_GLOBAL 2

#define FS_EXIT_PAC_FILE_NOT_FOUND 1000
#define FS_EXIT_PAC_WRONG_FORMAT 1001

/**
 * 初始化PAC模块
 * @param file_location IP白名单文件路径
 * @param mode PAC模式
 * @return 是否初始化成功
 */
extern bool pac_initial(const char* file_location, int mode);

/**
 * 判断IPv4地址是否需要代理
 * @param address IPv4地址，字节序为大端
 * @return 是否需要代理
 */
extern bool pac_need_proxy(in_addr_t address);

#ifdef __cplusplus
}
#endif

#endif //FS_PAC_H
