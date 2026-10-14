/*
 * Ships sealed segments to the archive agent that runs next to tbkeyd. The agent holds the object
 * store credentials and does its own transport security; tbkeyd talks plain HTTP to it on the
 * loopback interface. A segment that fails to ship stays in the spool directory and is retried.
 */
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#include "keyd/audit.h"
#include "keyd/keyd.h"
#include "keyd/paths.h"
#include "util/log.h"

#define AGENT_TIMEOUT_S 10

static int connect_agent(const char *host, unsigned short port)
{
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof addr);
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    if (inet_pton(AF_INET, host, &addr.sin_addr) != 1)
        return -1;

    int fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0)
        return -1;
    struct timeval tv = { .tv_sec = AGENT_TIMEOUT_S, .tv_usec = 0 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);
    if (connect(fd, (struct sockaddr *)&addr, sizeof addr) != 0) {
        close(fd);
        return -1;
    }
    return fd;
}

static int send_all(int fd, const void *p, size_t len)
{
    const unsigned char *b = p;
    while (len > 0) {
        ssize_t n = send(fd, b, len, MSG_NOSIGNAL);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        b += n;
        len -= (size_t)n;
    }
    return 0;
}

static int read_status(int fd)
{
    char line[128];
    size_t n = 0;
    while (n + 1 < sizeof line) {
        ssize_t r = recv(fd, line + n, 1, 0);
        if (r <= 0)
            return -1;
        if (line[n] == '\n')
            break;
        n++;
    }
    line[n] = '\0';
    int status = 0;
    if (sscanf(line, "HTTP/1.%*d %d", &status) != 1)
        return -1;
    return status;
}

int keyd_segment_ship(const char *agent_host, unsigned short agent_port, const char *segment_id,
                      const unsigned char *body, size_t body_len)
{
    char head[512];
    int fd = connect_agent(agent_host, agent_port);
    if (fd < 0) {
        log_warn("audit: archive agent %s:%u unreachable, segment %s stays spooled", agent_host,
                 (unsigned)agent_port, segment_id);
        return KEYD_ERR_IO;
    }
    int n = snprintf(head, sizeof head,
                     "PUT /v1/segments/tbkeyd/%s HTTP/1.1\r\n"
                     "Host: %s:%u\r\n"
                     "Content-Type: application/octet-stream\r\n"
                     "Content-Length: %zu\r\n"
                     "Connection: close\r\n\r\n",
                     segment_id, agent_host, (unsigned)agent_port, body_len);
    int rc = KEYD_ERR_IO;
    if (n > 0 && (size_t)n < sizeof head && send_all(fd, head, (size_t)n) == 0 && send_all(fd, body, body_len) == 0) {
        int status = read_status(fd);
        if (status == 201 || status == 200)
            rc = KEYD_OK;
        else
            log_warn("audit: archive agent answered %d for segment %s", status, segment_id);
    }
    close(fd);
    return rc;
}

int keyd_segment_spool(const char *segment_id, const unsigned char *body, size_t body_len)
{
    char path[512];
    snprintf(path, sizeof path, "%s/%s.seg", KEYD_SPOOL_DIR, segment_id);
    return keyd_write_file(path, body, body_len, 0600);
}
