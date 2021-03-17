//
// Created by lzf on 2021/2/21.
//

#include "buffer.h"
#include "logger.h"
#include <unistd.h>
#include <stdlib.h>

#ifdef __BIG_ENDIAN__
#define htonll(x) (x)
#define ntohll(x) (x)
#else
#define htonll(x) (((uint64_t)htonl((x) & 0xFFFFFFFF) << 32) | htonl((x) >> 32))
#define ntohll(x) (((uint64_t)ntohl((x) & 0xFFFFFFFF) << 32) | ntohl((x) >> 32))
#endif

struct byte_buf_s {
    // 内存区域
    void *memory;

    // 内存大小
    size_t size;

    // 引用计数
    int32_t refcnt;

    // 读索引
    int32_t idx_read;

    // 写索引
    int32_t idx_write;

    // memory是否是被包装的
    bool wrap;
};

byte_buf_t* byte_buf_new(size_t size) {
    if (size <= 0) {
        return NULL;
    }

    void* mem = malloc(size);
    if (mem == NULL) {
        log_error("Could not create ByteBuf memory, capacity: %d", size);
        return NULL;
    }

    byte_buf_t* buf = malloc(sizeof(byte_buf_t));
    if (buf == NULL) {
        free(mem);
        log_error("Could not create ByteBuf, capacity: %d", size);
        return NULL;
    }

    buf->memory = mem;
    buf->size = size;
    buf->refcnt = 1;
    buf->idx_write = 0;
    buf->idx_read = 0;
    buf->wrap = false;
    return buf;
}


byte_buf_t* byte_buf_wrap(void* memory, size_t size) {
    if (memory == NULL || size <= 0) {
        return NULL;
    }

    byte_buf_t* buf = malloc(sizeof(byte_buf_t));
    if (buf == NULL) {
        log_error("Could not create WRAP ByteBuf, capacity: %d", size);
        return NULL;
    }

    buf->memory = memory;
    buf->size = size;
    buf->refcnt = 1;
    buf->idx_write = 0;
    buf->idx_read = 0;
    buf->wrap = true;
    return buf;
}


bool byte_buf_set_write_index(byte_buf_t* buf, int32_t index) {
    if (buf == NULL || index < 0 || index >= buf->size) {
        return false;
    }
    buf->idx_write = index;
    return true;
}


bool byte_buf_is_full(byte_buf_t* buf) {
    return buf->idx_write >= buf->size;
}

int byte_buf_fd_read(byte_buf_t* buf, int fd) {
    void* memory = buf->memory + buf->idx_write;
    size_t size = buf->size - buf->idx_write;

    ssize_t length = read(fd, memory, size);
    if (length < 0) {
        return -1;
    }

    buf->idx_write += length;
    return length;
}


int byte_buf_event_read(byte_buf_t* buf, struct bufferevent* event) {
    void* memory = buf->memory + buf->idx_write;
    size_t size = buf->size - buf->idx_write;

    size_t length = bufferevent_read(event, memory, size);
    buf->idx_write += length;
    return length;
}

int byte_buf_event_write(byte_buf_t* buf, struct bufferevent* event) {
    void* memory = buf->memory + buf->idx_read;
    size_t size = buf->idx_write - buf->idx_read;
    if (size <= 0) {
        return 0;
    }
    /*int fd = bufferevent_getfd(event);
    int res = write(fd, memory, size);*/
    int res = bufferevent_write(event, memory, size);
    if (res == -1) {
        return -1;
    }

    buf->idx_read += size;
    return res;
}

int32_t byte_buf_readable_bytes(byte_buf_t* buf) {
    if (buf == NULL) {
        return -1;
    }
    return buf->idx_write - buf->idx_read;
}


int32_t byte_buf_writeable_bytes(byte_buf_t* buf) {
    if (buf == NULL) {
        return -1;
    }
    return buf->size - buf->idx_write;
}

bool byte_buf_write_byte(byte_buf_t* buf, uint8_t b) {
    int length = sizeof(uint8_t);
    int32_t idx = buf->idx_write;
    if (idx + length > buf->size) {
        return false;
    }

    uint8_t* addr = buf->memory + idx;
    *addr = b;
    buf->idx_write = idx + length;
    return true;
}

bool byte_buf_write_char(byte_buf_t* buf, char c) {
    int length = sizeof(char);
    int32_t idx = buf->idx_write;
    if (idx + length > buf->size) {
        return false;
    }

    char* addr = buf->memory + idx;
    *addr = c;
    buf->idx_write = idx + length;
    return true;
}


bool byte_buf_write_chars(byte_buf_t* buf, const char* string, int length) {
    if (buf == NULL || string == NULL || length <= 0) {
        return false;
    }

    char* addr = buf->memory + buf->idx_write;
    for (int i = 0; i < length; i++) {
        addr[i] = string[i];
    }
    buf->idx_write += length;
    return true;
}


bool byte_buf_write_short(byte_buf_t* buf, int16_t number) {
    int length = sizeof(int16_t);
    int32_t idx = buf->idx_write;
    if (idx + length > buf->size) {
        return false;
    }

    int16_t* addr = buf->memory + idx;
    *addr = htons(number);
    buf->idx_write = idx + length;
    return true;
}

bool byte_buf_write_ushort(byte_buf_t* buf, uint16_t number) {
    int length = sizeof(uint16_t);
    int32_t idx = buf->idx_write;
    if (idx + length > buf->size) {
        return false;
    }

    uint16_t* addr = buf->memory + idx;
    *addr = htons(number);
    buf->idx_write = idx + length;
    return true;
}

bool byte_buf_write_int(byte_buf_t* buf, int32_t number) {
    int length = sizeof(int32_t);
    int32_t idx = buf->idx_write;
    if (idx + length > buf->size) {
        return false;
    }

    int32_t* addr = buf->memory + idx;
    *addr = htonl(number);
    buf->idx_write = idx + length;
    return true;
}

bool byte_buf_write_long(byte_buf_t* buf, int64_t number) {
    int length = sizeof(int64_t);
    int32_t idx = buf->idx_write;
    if (idx + length > buf->size) {
        return false;
    }

    int64_t* addr = buf->memory + idx;
    *addr = htonll(number);
    buf->idx_write = idx + length;
    return true;
}

bool byte_buf_read_byte(byte_buf_t* buf, uint8_t* dst) {
    int length = sizeof(uint8_t);
    int32_t idx = buf->idx_read;
    if (idx + length > buf->size  || idx + length > buf->idx_write) {
        return false;
    }

    uint8_t* addr = buf->memory + idx;
    *dst = *addr;
    buf->idx_read = idx + length;
    return true;
}

bool byte_buf_read_bytes(byte_buf_t* buf, void* dst, int length) {
    int32_t idx = buf->idx_read;
    if (idx + length > buf->size || idx + length > buf->idx_write) {
        return false;
    }

    uint8_t* target = (uint8_t*) dst;
    uint8_t* addr = buf->memory + idx;
    for (int i = 0; i < length; i++) {
        *(target + i) = *(addr + i);
    }

    buf->idx_read = idx + length;
    return true;
}

bool byte_buf_read_char(byte_buf_t* buf, char* dst) {
    int length = sizeof(char);
    int32_t idx = buf->idx_read;
    if (idx + length > buf->size || idx + length > buf->idx_write) {
        return false;
    }

    char* addr = buf->memory + idx;
    *dst = *addr;
    buf->idx_read = idx + length;
    return true;
}

bool byte_buf_read_short(byte_buf_t* buf, int16_t* dst) {
    int length = sizeof(int16_t);
    int32_t idx = buf->idx_read;
    if (idx + length > buf->size || idx + length > buf->idx_write) {
        return false;
    }

    int16_t* addr = buf->memory + idx;
    *dst = ntohs(*addr);
    buf->idx_read = idx + length;
    return true;
}

bool byte_buf_read_ushort(byte_buf_t* buf, uint16_t* dst) {
    int length = sizeof(uint16_t);
    int32_t idx = buf->idx_read;
    if (idx + length > buf->size || idx + length > buf->idx_write) {
        return false;
    }

    uint16_t* addr = buf->memory + idx;
    *dst = ntohs(*addr);
    buf->idx_read = idx + length;
    return true;
}

bool byte_buf_read_int(byte_buf_t* buf, int32_t* dst) {
    int length = sizeof(int32_t);
    int32_t idx = buf->idx_read;
    if (idx + length > buf->size || idx + length > buf->idx_write) {
        return false;
    }

    int32_t* addr = buf->memory + idx;
    *dst = ntohl(*addr);
    buf->idx_read = idx + length;
    return true;
}

bool byte_buf_read_uint(byte_buf_t* buf, uint32_t* dst) {
    int length = sizeof(uint32_t);
    int32_t idx = buf->idx_read;
    if (idx + length > buf->size || idx + length > buf->idx_write) {
        return false;
    }

    uint32_t* addr = buf->memory + idx;
    *dst = ntohl(*addr);
    buf->idx_read = idx + length;
    return true;
}

bool byte_buf_read_long(byte_buf_t* buf, int64_t* dst) {
    int length = sizeof(int64_t);
    int32_t idx = buf->idx_read;
    if (idx + length > buf->size || idx + length > buf->idx_write) {
        return false;
    }

    int64_t* addr = buf->memory + idx;
    *dst = ntohll(*addr);
    buf->idx_read = idx + length;
    return true;
}

bool byte_buf_read_chars(byte_buf_t* buf, char* dst, int length) {
    int32_t idx = buf->idx_read;

    if (length < 0 || idx + length > buf->size || idx + length > buf->idx_write) {
        return false;
    }

    char* addr = buf->memory + idx;
    for (int i = 0; i < length; i++) {
        *(dst + i) = *(addr + i);
    }

    buf->idx_read = idx + length;
    return true;
}


bool byte_buf_read_string(byte_buf_t* buf, char* dst, size_t dst_size) {
    if (dst_size == 0) {
        return false;
    } else if (dst_size == 1) {
        dst[0] = '\0';
        return false;
    }

    int32_t idx = buf->idx_read;
    char* addr = buf->memory + idx;

    int i;
    for (i = 0; i < dst_size; i++) {
        char c = *(addr + i);
        *(dst + i) = c;
        if (c == '\0') {
            i++;
            break;
        }
    }

    buf->idx_read = idx + i;
    if (i == dst_size) {
        dst[dst_size - 1] = '\0';
        return false;
    }
    return true;
}


bool byte_buf_transfer(byte_buf_t* src, byte_buf_t* dst, int length) {
    if (src == dst) {
        return true;
    }

    int32_t idx = src->idx_read;
    if (length < 0 || idx + length > src->idx_write || dst->idx_write + length > dst->size) {
        return false;
    }

    char* src_addr = src->memory + idx;
    char* dst_addr = dst->memory + dst->idx_write;
    for (int i = 0; i < length; i++) {
        *(dst_addr + i) = *(src_addr + i);
    }

    src->idx_read += length;
    dst->idx_write += length;
    return true;
}

byte_buf_t* byte_buf_retain(byte_buf_t* buf) {
    buf->refcnt++;
    return buf;
}

void byte_buf_release(byte_buf_t* buf) {
    int32_t refcnt = buf->refcnt;
    if (refcnt == 0) {
        log_error("Illegal byte buf operator: release, refCnt: %d", buf->refcnt);
        return;
    }

    refcnt--;
    if (refcnt == 0) {
        if (!buf->wrap) {
            free(buf->memory);
        }
        free(buf);
        return;
    }

    buf->refcnt = refcnt;
}