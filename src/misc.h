//
// Created by lzf on 2021/2/21.
//

#ifndef FS_MISC_H
#define FS_MISC_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>
#include "buffer.h"

/* 消息传输工具 */
typedef struct msg_deliver_s msg_deliverer_t;
typedef struct msg_deliver_receiver_s msg_deliver_receiver_t;

extern msg_deliverer_t* msg_deliver_new();
extern int msg_deliver_transfer(msg_deliverer_t* deliverer, byte_buf_t* buf);
extern int msg_deliver_set_receiver(msg_deliverer_t* deliverer, msg_deliver_receiver_t* receiver);
extern void msg_deliver_cancel(msg_deliverer_t* deliverer);
extern void msg_deliver_destroy(msg_deliverer_t* deliverer);
extern msg_deliver_receiver_t* msg_deliver_receiver_new(void (*receive_cb)(byte_buf_t*, void*), void (*close_cb)(void*), void* arg);

/* 字符串工具 */
typedef struct string_s string_t;

/**
 * 新建字符串，该操作会复制字符串
 * @param src 以空字符结尾的字符串
 * @return 字符串
 */
extern string_t* string_new(const char* src);

/**
 * 字符串长度，不包含结尾空字符
 * @return 字符串长度
 */
extern size_t string_length(string_t* string);

/**
 * 拼接C字符串到尾部
 * @return 是否拼接成功
 */
extern bool string_append(string_t* string, char* src);

/**
 * 拼接ASCII字符
 * @return 是否拼接成功
 */
extern bool string_append_char(string_t* string, char ch);

/**
 * 获取指定下标的ASCII字符
 * @return 字符，如果越界则返回空字符
 */
extern char string_get_char(string_t* string, int index);

/**
 * 获取字符串中最后一个ASCII字符
 */
extern char string_get_last_char(string_t* string);

/**
 * 获取字符串char指针，该操作不会复制字符串
 */
extern const char* string_get_content(string_t* string);

/**
 * 释放字符串内存空间
 */
extern void string_free(string_t* string);

/* 双端队列工具 */
typedef struct deque_s deque_t;

/**
 * 双端队列释放时对每个元素的操作回调
 */
typedef void (*deque_free_element_fn)(void* element, void* userdata);

/**
 * 新建双端队列
 * @param capacity 初始容量，要求为2的正整数次幂
 */
extern deque_t* deque_new(int capacity);

/**
 * @return 队列中包含的元素数量
 */
extern int32_t deque_elements_count(deque_t* deque);

/**
 * @return 队列是否不包含任何元素
 */
extern bool deque_is_empty(deque_t* queue);
/**
 * 添加元素到队列尾部
 * @param data 指向该元素的指针
 * @return 是否添加成功
 */
extern bool deque_offer_tail(deque_t* deque, void* data);

/**
 * 添加元素到队列头部
 * @param data 指向该元素的指针
 * @return 是否添加成功
 */
extern bool deque_offer_head(deque_t* deque, void* data);

/**
 * 取出队列尾部的元素
 * @return 指向该元素的指针，如果队列为空返回NULL
 */
extern void* deque_pop_tail(deque_t* deque);

/**
 * 取出队列头部的元素
 * @return 指向该元素的指针，如果队列为空返回NULL
 */
extern void* deque_pop_head(deque_t* deque);

/**
 * 查看队列尾部的元素
 * @return 指向该元素的指针，如果队列为空返回NULL
 */
extern void* deque_peek_tail(deque_t* deque);

/**
 * 清空队列元素
 * @param free_fn 元素释放回调函数
 * @param userdata 回调函数用户参数
 */
extern void deque_clear(deque_t* deque, deque_free_element_fn free_fn, void* userdata);

/**
 * 清空队列元素并释放队列
 * @param free_fn 元素释放回调函数
 * @param userdata 回调函数用户参数
 */
extern void deque_free(deque_t* deque, deque_free_element_fn free_fn, void* userdata);

/* BASE64编解码 */
extern char* base64_encode(char* plain);
extern char* base64_decode(char* cipher);

/** TCP辅助解码函数 */
extern bool message_decode_uint16(byte_buf_t* buffer, uint16_t* dest, uint32_t* hasread);
extern bool message_decode_uint16_le(byte_buf_t* buffer, uint16_t* dest, uint32_t* hasread);
extern bool message_decode_uint32(byte_buf_t* buffer, uint32_t* dest, uint32_t* hasread);
extern bool message_decode_bytes(byte_buf_t* buffer, byte_buf_t* dest, uint32_t* hasread, uint32_t mlen);
extern bool message_decode_string(byte_buf_t* buffer, char* dest, uint32_t* hasread, uint32_t mlen);

#ifdef __cplusplus
}
#endif

#endif
