//
// Created by lzf on 2021/2/21.
//

#ifndef FS_BUFFER_H
#define FS_BUFFER_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <event2/bufferevent.h>

typedef struct byte_buf_s byte_buf_t;

extern byte_buf_t* byte_buf_new(size_t size);
extern byte_buf_t* byte_buf_wrap(void* memory, size_t size);

extern bool byte_buf_is_full(byte_buf_t* buf);

extern int byte_buf_fd_read(byte_buf_t* buf, int fd);
extern int byte_buf_event_read(byte_buf_t* buf, struct bufferevent* event);
extern int byte_buf_event_write(byte_buf_t* buf, struct bufferevent* event);

extern int32_t byte_buf_readable_bytes(byte_buf_t* buf);
extern int32_t byte_buf_writeable_bytes(byte_buf_t* buf);

extern bool byte_buf_write_byte(byte_buf_t* buf, uint8_t b);
extern bool byte_buf_write_char(byte_buf_t* buf, char c);
extern bool byte_buf_write_string(byte_buf_t* buf, const char* string, int length);
extern bool byte_buf_write_short(byte_buf_t* buf, int16_t number);
extern bool byte_buf_write_ushort(byte_buf_t* buf, uint16_t number);
extern bool byte_buf_write_int(byte_buf_t* buf, int32_t number);
extern bool byte_buf_write_long(byte_buf_t* buf, int64_t number);

extern bool byte_buf_read_byte(byte_buf_t* buf, uint8_t* dst);
extern bool byte_buf_read_bytes(byte_buf_t* buf, void* dst, int length);
extern bool byte_buf_read_char(byte_buf_t* buf, char* dst);
extern bool byte_buf_read_short(byte_buf_t* buf, int16_t* dst);
extern bool byte_buf_read_ushort(byte_buf_t* buf, uint16_t* dst);
extern bool byte_buf_read_int(byte_buf_t* buf, int32_t* dst);
extern bool byte_buf_read_uint(byte_buf_t* buf, uint32_t* dst);
extern bool byte_buf_read_long(byte_buf_t* buf, int64_t* dst);
extern bool byte_buf_read_string(byte_buf_t* buf, char* dst, int length);

extern bool byte_buf_transfer(byte_buf_t* src, byte_buf_t* dst, int length);

extern byte_buf_t *byte_buf_retain(byte_buf_t *buf);
extern void byte_buf_release(byte_buf_t *buf);

#ifdef __cplusplus
}
#endif

#endif