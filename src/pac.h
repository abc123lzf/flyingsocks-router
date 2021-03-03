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

extern bool pac_need_proxy(uint32_t inAddr);

#ifdef __cplusplus
}
#endif

#endif //FS_PAC_H
