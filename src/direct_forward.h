//
// Created by lzf on 2021/2/21.
//

#ifndef FS_DIRECT_FORWARD_H
#define FS_DIRECT_FORWARD_H

#ifdef __cplusplus
extern "C" {
#endif

#include "service.h"

typedef struct direct_forward_ctx_s direct_forward_ctx_t;

extern direct_forward_ctx_t* direct_forward_init(service_ctx_t* service_ctx);
extern void direct_forward_run(direct_forward_ctx_t* ctx);
extern void direct_forward_stop(direct_forward_ctx_t* ctx);

#ifdef __cplusplus
}
#endif

#endif
