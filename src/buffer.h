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

#include <event2/buffer.h>
#include <event2/bufferevent.h>

typedef struct byte_buf_s byte_buf_t;

/**
 * 构造一个新的字节缓冲区
 * @param size 缓冲区大小
 * @return 字节缓冲区
 */
extern byte_buf_t* byte_buf_new(size_t size);

/**
 * 将一段内存包装为一个字节缓冲区
 * @param memory 需要包装的内存
 * @param size 使用该内存的最大长度
 * @return 字节缓冲区
 */
extern byte_buf_t* byte_buf_wrap(void* memory, size_t size);

/**
 * 重新设置写索引，不能超过该字节缓冲区的容量
 */
extern bool byte_buf_set_write_index(byte_buf_t* buf, int32_t index);

/**
 * @return 该字节缓冲区是否已满（写索引是否等于容量）
 */
extern bool byte_buf_is_full(byte_buf_t* buf);

/**
 * 从文件描述符中读取数据
 * @return 读取的字节数
 */
extern int byte_buf_fd_read(byte_buf_t* buf, int fd);

/**
 * 从BufferEvent中读取数据
 * @return 读取的字节数
 */
extern int byte_buf_event_read(byte_buf_t* buf, struct bufferevent* event);

/**
 * 向BufferEvent写入数据
 * @return 写入的字节数
 */
extern int byte_buf_event_write(byte_buf_t* buf, struct bufferevent* event);

/**
 * @return 字节缓冲区可读字节数
 */
extern int32_t byte_buf_readable_bytes(byte_buf_t* buf);

/**
 * @return 字节缓冲区可写字节数
 */
extern int32_t byte_buf_writeable_bytes(byte_buf_t* buf);

extern bool byte_buf_write_byte(byte_buf_t* buf, uint8_t b);
extern bool byte_buf_write_char(byte_buf_t* buf, char c);
extern bool byte_buf_write_chars(byte_buf_t* buf, const char* string, int length);
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
extern bool byte_buf_read_chars(byte_buf_t* buf, char* dst, int length);
extern bool byte_buf_read_string(byte_buf_t* buf, char* dst, size_t dst_size);

/**
 * 将字节缓冲区中的内容复制到另外一个字节缓冲区
 * @param src 源字节缓冲区
 * @param dst 目标字节缓冲区
 * @param length 复制的字节数
 * @return 是否复制成功
 */
extern bool byte_buf_transfer(byte_buf_t* src, byte_buf_t* dst, int length);

/**
 * 将字节缓冲区引用计数加1
 */
extern byte_buf_t* byte_buf_retain(byte_buf_t* buf);

/**
 * 将字节缓冲区引用计数减1，如果此时引用计数为0则该字节缓冲区会被释放
 */
extern void byte_buf_release(byte_buf_t* buf);

#ifdef __cplusplus
}
#endif

#endif