/* Byte buffers, whole-file I/O and status strings. */
#include "keyd/keyd.h"

#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

int keyd_buf_reserve(struct keyd_buf *b, size_t extra)
{
    if (b->len + extra <= b->cap)
        return KEYD_OK;
    size_t cap = b->cap ? b->cap : 256;
    while (cap < b->len + extra) {
        if (cap > SIZE_MAX / 2)
            return KEYD_ERR_NOMEM;
        cap *= 2;
    }
    unsigned char *p = realloc(b->data, cap);
    if (p == NULL)
        return KEYD_ERR_NOMEM;
    b->data = p;
    b->cap = cap;
    return KEYD_OK;
}

int keyd_buf_append(struct keyd_buf *b, const void *p, size_t n)
{
    int rc = keyd_buf_reserve(b, n);
    if (rc != KEYD_OK)
        return rc;
    if (n > 0)
        memcpy(b->data + b->len, p, n);
    b->len += n;
    return KEYD_OK;
}

int keyd_buf_printf(struct keyd_buf *b, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    int need = vsnprintf(NULL, 0, fmt, ap);
    va_end(ap);
    if (need < 0)
        return KEYD_ERR_ARGS;
    int rc = keyd_buf_reserve(b, (size_t)need + 1);
    if (rc != KEYD_OK)
        return rc;
    va_start(ap, fmt);
    vsnprintf((char *)b->data + b->len, (size_t)need + 1, fmt, ap);
    va_end(ap);
    b->len += (size_t)need;
    return KEYD_OK;
}

void keyd_buf_reset(struct keyd_buf *b)
{
    if (b->data != NULL)
        memset(b->data, 0, b->cap);
    b->len = 0;
}

void keyd_buf_free(struct keyd_buf *b)
{
    keyd_buf_reset(b);
    free(b->data);
    b->data = NULL;
    b->cap = 0;
}

const char *keyd_status_str(int status)
{
    switch (status) {
    case KEYD_OK:
        return "ok";
    case KEYD_ERR_ARGS:
        return "bad arguments";
    case KEYD_ERR_NOMEM:
        return "out of memory";
    case KEYD_ERR_IO:
        return "i/o error";
    case KEYD_ERR_LIB:
        return "library error";
    case KEYD_ERR_TOKEN:
        return "token error";
    case KEYD_ERR_AUTH:
        return "not authorised";
    case KEYD_ERR_POLICY:
        return "refused by policy";
    case KEYD_ERR_NOTFOUND:
        return "not found";
    default:
        return "unknown error";
    }
}

int keyd_read_file(const char *path, size_t max, struct keyd_buf *out)
{
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return errno == ENOENT ? KEYD_ERR_NOTFOUND : KEYD_ERR_IO;

    int rc = KEYD_OK;
    for (;;) {
        if ((rc = keyd_buf_reserve(out, 4096)) != KEYD_OK)
            break;
        ssize_t n = read(fd, out->data + out->len, out->cap - out->len);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            rc = KEYD_ERR_IO;
            break;
        }
        if (n == 0)
            break;
        out->len += (size_t)n;
        if (out->len > max) {
            rc = KEYD_ERR_ARGS;
            break;
        }
    }
    close(fd);
    return rc;
}

int keyd_write_file(const char *path, const void *data, size_t len, unsigned int mode)
{
    char tmp[4096];
    if (snprintf(tmp, sizeof tmp, "%s.tmp.%ld", path, (long)getpid()) >= (int)sizeof tmp)
        return KEYD_ERR_ARGS;

    int fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, (mode_t)mode);
    if (fd < 0)
        return KEYD_ERR_IO;

    const unsigned char *p = data;
    size_t left = len;
    while (left > 0) {
        ssize_t n = write(fd, p, left);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            close(fd);
            unlink(tmp);
            return KEYD_ERR_IO;
        }
        p += n;
        left -= (size_t)n;
    }
    if (fsync(fd) != 0 || close(fd) != 0) {
        unlink(tmp);
        return KEYD_ERR_IO;
    }
    if (rename(tmp, path) != 0) {
        unlink(tmp);
        return KEYD_ERR_IO;
    }
    return KEYD_OK;
}
