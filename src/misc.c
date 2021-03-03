//
// Created by lzf on 2021/2/21.
//
#include "misc.h"
#include "logger.h"
#include <stdlib.h>
#include <iconv.h>

struct msg_deliver_receiver_s {
    // 消息接收回调
    void (*receive_cb)(byte_buf_t *buf, void *);
    // 客户端会话关闭回调
    void (*close_cb)(void *);
    // 回调用户参数
    void *cb_arg;
};

struct msg_deliver_s {
    bool cancel;
    deque_t *queue;
    msg_deliver_receiver_t *receiver;
};

struct string_s {
    char *memory;
    size_t length;
    size_t size;
};

struct deque_s {
    void **array;
    int32_t capacity;
    int32_t head;
    int32_t tail;
};

static bool deque_double_capacity(deque_t *deque);

const static char base46_map[] = {'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
                                  'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
                                  'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
                                  'w', 'x', 'y', 'z', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '+', '/'};

msg_deliverer_t *msg_deliver_new() {
    msg_deliverer_t *deliverer = malloc(sizeof(msg_deliverer_t));
    if (deliverer == NULL) {
        return NULL;
    }

    deliverer->cancel = false;
    deliverer->queue = deque_new(16);
    deliverer->receiver = NULL;
    return deliverer;
}


int msg_deliver_transfer(msg_deliverer_t *deliverer, byte_buf_t *buf) {
    if (deliverer == NULL || buf == NULL) {
        return -1;
    }

    if (deliverer->cancel) {
        return 1;
    }

    if (deliverer->receiver != NULL) {
        msg_deliver_receiver_t *receiver = deliverer->receiver;
        receiver->receive_cb(byte_buf_retain(buf), receiver->cb_arg);
        return 0;
    }

    msg_deliver_receiver_t *receiver = deliverer->receiver;
    if (receiver == NULL) {
        deque_offer_tail(deliverer->queue, byte_buf_retain(buf));
        return 0;
    }

    receiver->receive_cb(byte_buf_retain(buf), receiver->cb_arg);
    return 0;
}

int msg_deliver_set_receiver(msg_deliverer_t *deliverer, msg_deliver_receiver_t *receiver) {
    if (deliverer == NULL || receiver == NULL || receiver->receive_cb == NULL) {
        return -1;
    }

    if (deliverer->cancel) {
        return 1;
    }

    deque_t *queue = deliverer->queue;
    int size = deque_elements_count(queue);
    for (int i = 0; i < size; i++) {
        byte_buf_t *buf = deque_pop_head(queue);
        receiver->receive_cb(buf, receiver->cb_arg);
    }

    deque_free(queue, NULL, NULL);
    deliverer->queue = NULL;
    deliverer->receiver = receiver;
    return 0;
}

void msg_deliver_cancel(msg_deliverer_t *deliverer) {
    if (deliverer == NULL) {
        return;
    }

    deliverer->cancel = true;
    msg_deliver_receiver_t *receiver = deliverer->receiver;
    if (receiver != NULL) {
        if (receiver->close_cb != NULL) {
            receiver->close_cb(receiver->cb_arg);
        }
        free(receiver);
    }

    deque_t *queue = deliverer->queue;
    if (queue != NULL) {
        int size = deque_elements_count(queue);
        for (int i = 0; i < size; i++) {
            byte_buf_t *buf = deque_pop_head(queue);
            byte_buf_release(buf);
        }
        deque_free(queue, NULL, NULL);
    }
}


void msg_deliver_destroy(msg_deliverer_t *deliverer) {
    if (!deliverer->cancel) {
        log_warn("MessageDeliver destroy failure: not cancel");
        return;
    }
    free(deliverer);
}


msg_deliver_receiver_t *
msg_deliver_receiver_new(void (*receive_cb)(byte_buf_t *, void *), void (*close_cb)(void *), void *arg) {
    msg_deliver_receiver_t *receiver = malloc(sizeof(msg_deliver_receiver_t));
    if (receiver == NULL) {
        return NULL;
    }
    receiver->receive_cb = receive_cb != NULL ? receive_cb : NULL;
    receiver->close_cb = close_cb != NULL ? close_cb : NULL;
    receiver->cb_arg = arg;
    return receiver;
}

string_t *string_new(const char *src) {
    string_t *string = malloc(sizeof(string_t));
    if (string == NULL) {
        return NULL;
    }

    if (src == NULL) {
        string->memory = NULL;
        string->length = 0;
        string->size = 0;
        return string;
    }

    size_t len = strlen(src);
    char *copy = malloc(len + 1);
    if (copy == NULL) {
        free(string);
        return NULL;
    }

    strcpy(copy, src);
    string->memory = copy;
    string->length = len;
    string->size = len + 1;

    return string;
}

size_t string_length(string_t *string) {
    return string->length;
}

bool string_append(string_t *string, char *src) {
    if (src == NULL) {
        return true;
    }

    size_t src_len = strlen(src);
    if (string->length + src_len + 1 <= string->size) {
        strcat(string->memory, src);
        return true;
    }

    size_t new_size = src_len <= 250 ? string->length + src_len * 2 : string->length + src_len + 250;
    char *new_memory = malloc(new_size);
    if (new_memory == NULL) {
        return false;
    }

    char *old_memory = string->memory;
    strcpy(new_memory, old_memory);
    strcat(new_memory, src);
    free(old_memory);
    string->memory = new_memory;
    string->length += src_len;
    string->size = new_size;
    return true;
}

bool string_append_char(string_t *string, char ch) {
    char src[] = {ch, '\0'};
    return string_append(string, src);
}


char string_get_char(string_t *string, int index) {
    if (string == NULL) {
        return '\0';
    }

    char *memory = string->memory;
    if (memory == NULL || index >= string->length) {
        return '\0';
    }

    return memory[index];
}

char string_get_last_char(string_t *string) {
    if (string == NULL) {
        return '\0';
    }

    size_t len = string->length;
    if (len == 0) {
        return '\0';
    }

    char *memory = string->memory;
    return memory[len - 1];
}


const char *string_get_content(string_t *string) {
    if (string == NULL) {
        return NULL;
    }
    return string->memory;
}

void string_free(string_t *string) {
    if (string == NULL) {
        return;
    }

    free(string->memory);
    free(string);
}

deque_t *deque_new(int capacity) {
    int32_t real_size = 8;
    if (capacity >= real_size) {
        real_size = capacity;
        real_size |= (real_size >> 1);
        real_size |= (real_size >> 2);
        real_size |= (real_size >> 4);
        real_size |= (real_size >> 8);
        real_size |= (real_size >> 16);
        real_size++;

        if (real_size < 0) {
            real_size >>= 1;
        }
    }

    void **array = calloc(real_size, sizeof(void *));
    if (array == NULL) {
        return NULL;
    }

    deque_t *deque = malloc(sizeof(deque_t));
    if (deque == NULL) {
        free(array);
        return NULL;
    }

    deque->array = array;
    deque->capacity = real_size;
    deque->head = 0;
    deque->tail = 0;

    return deque;
}

int32_t deque_elements_count(deque_t *deque) {
    if (deque == NULL) {
        return -1;
    }

    return (deque->tail - deque->head) & (deque->capacity - 1);
}

bool deque_is_empty(deque_t *queue) {
    return queue != NULL ? queue->head == queue->tail : true;
}

bool deque_offer_tail(deque_t *deque, void *data) {
    if (deque == NULL || data == NULL) {
        return false;
    }

    void **array = deque->array;
    int32_t tail = deque->tail;
    int32_t head = deque->head;
    int32_t capacity = deque->capacity;

    array[tail] = data;

    tail = (tail + 1) & (capacity - 1);
    if (tail == head) {
        return deque_double_capacity(deque);
    }
    deque->tail = tail;
    return true;
}

bool deque_offer_head(deque_t *deque, void *data) {
    if (deque == NULL || data == NULL) {
        return false;
    }

    void **array = deque->array;
    int32_t tail = deque->tail;
    int32_t head = deque->head;
    int32_t capacity = deque->capacity;

    head = (head - 1) & (capacity - 1);
    array[head] = data;
    if (head == tail) {
        return deque_double_capacity(deque);
    }

    deque->head = head;
    return true;
}

void *deque_pop_tail(deque_t *deque) {
    if (deque == NULL) {
        return NULL;
    }

    void **array = deque->array;
    int32_t t = (deque->tail - 1) & (deque->capacity - 1);
    void *result = array[t];
    if (result == NULL) {
        return NULL;
    }

    array[t] = NULL;
    deque->tail = t;
    return result;
}

void *deque_pop_head(deque_t *deque) {
    if (deque == NULL) {
        return NULL;
    }

    int32_t h = deque->head;
    void **array = deque->array;

    void *result = array[h];
    if (result == NULL) {
        return NULL;
    }

    array[h] = NULL;
    deque->head = (h + 1) & (deque->capacity - 1);
    return result;
}

static bool deque_double_capacity(deque_t *deque) {
    int32_t p = deque->head;
    int32_t n = deque->capacity;
    int32_t r = n - p;
    int new_capacity = n << 1;
    if (new_capacity < 0) {
        return false;
    }

    void **new_array = calloc(new_capacity, sizeof(void *));
    if (new_array == NULL) {
        return false;
    }

    void **array = deque->array;
    for (int i = 0; i < r; i++) {
        new_array[i] = array[p + i];
    }

    for (int i = 0; i < p; i++) {
        new_array[r + i] = array[i];
    }

    deque->array = new_array;
    deque->capacity = new_capacity;
    deque->head = 0;
    deque->tail = n;
    free(array);
    return true;
}

void *deque_peek_tail(deque_t *deque) {
    if (deque == NULL) {
        return NULL;
    }

    return deque->array[(deque->tail - 1) & (deque->capacity - 1)];
}

void deque_clear(deque_t *deque, deque_free_element_fn free_fn, void *userdata) {
    void **array = deque->array;
    if (free_fn != NULL) {
        int32_t h = deque->head;
        int32_t t = deque->tail;
        if (h != t) {
            deque->head = 0;
            deque->tail = 0;
            int32_t i = h;
            int mask = deque->capacity - 1;
            do {
                free_fn(array[i], userdata);
                array[i] = NULL;
                i = (i + 1) & mask;
            } while (i != t);
        }
    }
}

void deque_free(deque_t *deque, deque_free_element_fn free_fn, void *userdata) {
    void **array = deque->array;
    deque_clear(deque, free_fn, userdata);
    free(array);
    free(deque);
}


char* base64_encode(char *plain) {
    char counts = 0;
    char buffer[3];
    char *cipher = malloc(strlen(plain) * 4 / 3 + 4);
    int c = 0;

    for (int i = 0; plain[i] != '\0'; i++) {
        buffer[counts++] = plain[i];
        if (counts == 3) {
            cipher[c++] = base46_map[buffer[0] >> 2];
            cipher[c++] = base46_map[((buffer[0] & 0x03) << 4) + (buffer[1] >> 4)];
            cipher[c++] = base46_map[((buffer[1] & 0x0f) << 2) + (buffer[2] >> 6)];
            cipher[c++] = base46_map[buffer[2] & 0x3f];
            counts = 0;
        }
    }

    if (counts > 0) {
        cipher[c++] = base46_map[buffer[0] >> 2];
        if (counts == 1) {
            cipher[c++] = base46_map[(buffer[0] & 0x03) << 4];
            cipher[c++] = '=';
        } else {
            cipher[c++] = base46_map[((buffer[0] & 0x03) << 4) + (buffer[1] >> 4)];
            cipher[c++] = base46_map[(buffer[1] & 0x0f) << 2];
        }
        cipher[c++] = '=';
    }

    cipher[c] = '\0';
    return cipher;
}


char* base64_decode(char *cipher) {
    char counts = 0;
    char buffer[4];
    char *plain = malloc(strlen(cipher) * 3 / 4);
    int p = 0;

    for (int i = 0; cipher[i] != '\0'; i++) {
        char k;
        for (k = 0; k < 64 && base46_map[k] != cipher[i]; k++);
        buffer[counts++] = k;
        if (counts == 4) {
            plain[p++] = (buffer[0] << 2) + (buffer[1] >> 4);
            if (buffer[2] != 64) {
                plain[p++] = (buffer[1] << 4) + (buffer[2] >> 2);
            }
            if (buffer[3] != 64) {
                plain[p++] = (buffer[2] << 6) + buffer[3];
            }
            counts = 0;
        }
    }

    plain[p] = '\0';
    return plain;
}
