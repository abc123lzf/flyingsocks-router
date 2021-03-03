//
// Created by lzf on 2021/2/21.
//

#include "pac.h"
#include <linux/socket.h>

struct pac_ctx_s {

};

typedef struct pac_ctx_s pac_ctx_t;

bool pac_need_proxy(uint32_t inAddr) {
    return true;
}