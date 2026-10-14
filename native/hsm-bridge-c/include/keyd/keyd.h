/* Common types for tbkeyd. */
#ifndef KEYD_KEYD_H
#define KEYD_KEYD_H

#include <stddef.h>
#include <stdint.h>

#define KEYD_VERSION "4.2.0"

enum keyd_status {
    KEYD_OK = 0,
    KEYD_ERR_ARGS = -1,
    KEYD_ERR_NOMEM = -2,
    KEYD_ERR_IO = -3,
    KEYD_ERR_LIB = -4,
    KEYD_ERR_TOKEN = -5,
    KEYD_ERR_AUTH = -6,
    KEYD_ERR_POLICY = -7,
    KEYD_ERR_NOTFOUND = -8,
};

/* Growable byte buffer used by the request layer and the exporters. */
struct keyd_buf {
    unsigned char *data;
    size_t len;
    size_t cap;
};

int keyd_buf_reserve(struct keyd_buf *b, size_t extra);
int keyd_buf_append(struct keyd_buf *b, const void *p, size_t n);
int keyd_buf_printf(struct keyd_buf *b, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
void keyd_buf_reset(struct keyd_buf *b);
void keyd_buf_free(struct keyd_buf *b);

const char *keyd_status_str(int status);

/* Read a whole file (at most max bytes) into a fresh buffer. */
int keyd_read_file(const char *path, size_t max, struct keyd_buf *out);
/* Write a file atomically: temp file in the same directory, fsync, rename. */
int keyd_write_file(const char *path, const void *data, size_t len, unsigned int mode);

/* A depot as tbkeyd knows it: number, region and the keys derived for it. */
struct depot {
    uint64_t number;
    char code[8];
    char region[16];
    unsigned char ack_key[32];
};

#endif
