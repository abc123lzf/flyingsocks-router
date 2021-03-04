//
// Created by lzf on 2021/2/21.
//

#include "pac.h"
#include "logger.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef FS_PAC_MAX_ITEMS
#define FS_PAC_MAX_ITEMS 10000
#endif

struct ipv4_item {
    uint32_t network;
    uint32_t netmask;
};

struct pac_ctx_s {
    int size;
    int mode;
    bool initial;
    struct ipv4_item* items;
};


typedef struct pac_ctx_s pac_ctx_t;

static pac_ctx_t pac_ctx = {0};

static inline void pac_parse_item(struct ipv4_item* dest, char* ip, char* mask) {
    in_addr_t addr = inet_addr(ip);
    int masknum = atoi(mask);
    if (masknum < 0 || masknum > 32) {
        exit(FS_EXIT_PAC_WRONG_FORMAT);
    }

    uint32_t netmask = 0xFFFFFFFF << (32 - masknum);
    dest->network = ntohl(addr);
    dest->netmask = netmask;
}

static int ipv4_item_cmp(const void* v1, const void* v2) {
    struct ipv4_item* a = (struct ipv4_item*) v1;
    struct ipv4_item* b = (struct ipv4_item*) v2;
    if (a->network == b->network) {
        return 0;
    }
    return a->network < b->network ? -1 : 1;
}


bool pac_initial(const char* file_location, int mode) {
    if (mode != FS_PAC_MODE_GLOBAL && mode != FS_PAC_MODE_NO_PROXY && mode != FS_PAC_MODE_IP_WHITELIST) {
        return false;
    }

    if (pac_ctx.initial) {
        return false;
    }

    if (mode == FS_PAC_MODE_GLOBAL || mode == FS_PAC_MODE_NO_PROXY) {
        pac_ctx.initial = true;
        pac_ctx.size = 0;
        pac_ctx.mode = mode;
        return true;
    }

    FILE* file = fopen(file_location, "r");
    if (file == NULL) {
        exit(FS_EXIT_PAC_FILE_NOT_FOUND);
    }

    pac_ctx.items = malloc(sizeof(struct ipv4_item) * FS_PAC_MAX_ITEMS);

    int count = 0;
    char line[25];
    char ip[18], mask[3];
    while (fgets(line, sizeof(line), file) != NULL) {
        if (line[0] == '#') {
            continue;
        }

        int pos = 0;
        int len = strnlen(line, sizeof(line));
        while (line[pos] != '/' && pos < 25) {
            pos++;
        }

        if (pos == sizeof(line)) {
            line[sizeof(line) - 1] = '\0';
            log_error("PAC: Unknow ip rules: %s", line);
            exit(FS_EXIT_PAC_WRONG_FORMAT);
        }

        strncpy(ip, line, pos);
        strncpy(mask, line + pos + 1, len - pos);

        pac_parse_item(&pac_ctx.items[count], ip, mask);
        count++;
    }

    pac_ctx.size = count;
    fclose(file);
    qsort(pac_ctx.items, pac_ctx.size, sizeof(struct ipv4_item), ipv4_item_cmp);
    return true;
}


static struct ipv4_item* search_ipv4_item(uint32_t addr) {
    int low = 0;
    int high = pac_ctx.size - 1;
    while (low <= high) {
        int mid = (low + high) >> 1;
        struct ipv4_item* midval = &pac_ctx.items[mid];
        if (midval->network < addr) {
            low = mid + 1;
        } else if (midval->network > addr) {
            high = mid - 1;
        } else {
            return midval;
        }
    }
    return &pac_ctx.items[low];
}


bool pac_need_proxy(in_addr_t address) {
    if (pac_ctx.mode == FS_PAC_MODE_NO_PROXY) {
        return false;
    } else if (pac_ctx.mode == FS_PAC_MODE_GLOBAL) {
        return true;
    }

    address = ntohl(address);
    struct ipv4_item* item = search_ipv4_item(address);
    return (address & item->netmask) != (item->network & item->netmask);
}