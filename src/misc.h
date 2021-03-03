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
extern string_t* string_new(const char* src);
extern size_t string_length(string_t* string);
extern bool string_append(string_t* string, char* src);
extern bool string_append_char(string_t* string, char ch);
extern char string_get_char(string_t* string, int index);
extern char string_get_last_char(string_t* string);
extern const char* string_get_content(string_t* string);
extern void string_free(string_t* string);

/* 双端队列工具 */
typedef struct deque_s deque_t;
typedef void (*deque_free_element_fn)(void* element, void* userdata);
extern deque_t* deque_new(int capacity);
extern int32_t deque_elements_count(deque_t* deque);
extern bool deque_is_empty(deque_t* queue);
extern bool deque_offer_tail(deque_t* deque, void* data);
extern bool deque_offer_head(deque_t* deque, void* data);
extern void* deque_pop_tail(deque_t* deque);
extern void* deque_pop_head(deque_t* deque);
extern void* deque_peek_tail(deque_t* deque);
extern void deque_clear(deque_t* deque, deque_free_element_fn free_fn, void* userdata);
extern void deque_free(deque_t* deque, deque_free_element_fn free_fn, void* userdata);

/* BASE64编解码 */
extern char* base64_encode(char* plain);
extern char* base64_decode(char* cipher);

#ifdef __cplusplus
}
#endif

#endif
