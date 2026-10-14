/*
 * tbkeyd: key custody daemon.
 *
 *   tbkeyd [-c keyd.conf] [-f]      run (systemd starts it in the foreground)
 *   tbkeyd --self-check             library self-check, used as ExecStartPre
 *   tbkeyd --version
 *
 * Start-up order matters: the audit chain opens first so that everything after it is recorded,
 * then the vault gives us the partition PIN, then the partition objects are checked, and only then
 * does the listener accept clients.
 */

#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <getopt.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#include "api/handlers.h"
#include "config/config.h"
#include "keyd/audit.h"
#include "keyd/crypto_api.h"
#include "keyd/export.h"
#include "keyd/hsm.h"
#include "keyd/keyd.h"
#include "keyd/link.h"
#include "keyd/paths.h"
#include "keyd/tls_profile.h"
#include "selfcheck.h"
#include "tls/tls_server.h"
#include "util/crypto_util.h"
#include "util/log.h"

static volatile sig_atomic_t stopping;

static void on_signal(int sig)
{
    (void)sig;
    stopping = 1;
}

static void usage(FILE *out)
{
    fprintf(out, "usage: tbkeyd [-c config] [-f] | --self-check | --version\n");
}

static int read_credential(const char *name, char *out, size_t cap)
{
    char path[512];
    const char *dir = getenv("CREDENTIALS_DIRECTORY");
    struct keyd_buf b = { 0 };
    if (dir == NULL)
        return KEYD_ERR_NOTFOUND;
    snprintf(path, sizeof path, "%s/%s", dir, name);
    int rc = keyd_read_file(path, cap - 1, &b);
    if (rc == KEYD_OK) {
        while (b.len > 0 && (b.data[b.len - 1] == '\n' || b.data[b.len - 1] == '\r'))
            b.len--;
        memcpy(out, b.data, b.len);
        out[b.len] = '\0';
    }
    keyd_buf_free(&b);
    return rc;
}

static int open_audit(void)
{
    unsigned char key[64];
    struct keyd_buf b = { 0 };
    int rc = keyd_read_file(KEYD_SECRETS_DIR "/audit-chain.key", sizeof key, &b);
    if (rc == KEYD_OK && b.len != sizeof key)
        rc = KEYD_ERR_ARGS;
    if (rc == KEYD_OK) {
        memcpy(key, b.data, sizeof key);
        rc = keyd_audit_open(KEYD_AUDIT_DIR, key, sizeof key);
    }
    crypto_wipe(key, sizeof key);
    keyd_buf_free(&b);
    return rc;
}

static int open_partition(struct keyd_p11 *p, const struct keyd_config *cfg)
{
    char passphrase[256], pin[65];
    int rc = read_credential("vault-passphrase", passphrase, sizeof passphrase);
    if (rc != KEYD_OK) {
        log_err("start-up: no vault passphrase credential");
        return rc;
    }
    rc = keyd_vault_unlock_pin(KEYD_VAULT_FILE, passphrase, pin, sizeof pin);
    crypto_wipe(passphrase, sizeof passphrase);
    if (rc != KEYD_OK)
        return rc;
    rc = keyd_p11_open(p, cfg->p11_module, cfg->p11_slot_label);
    if (rc == KEYD_OK)
        rc = keyd_p11_login(p, pin, strlen(pin));
    crypto_wipe(pin, sizeof pin);
    if (rc == KEYD_OK)
        rc = keyd_p11_ensure_objects(p);
    return rc;
}

static int listen_socket(const struct keyd_config *cfg)
{
    struct sockaddr_in addr;
    int one = 1;
    memset(&addr, 0, sizeof addr);
    addr.sin_family = AF_INET;
    addr.sin_port = htons(cfg->listen_port);
    if (inet_pton(AF_INET, cfg->listen_addr, &addr.sin_addr) != 1)
        return -1;
    int fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0)
        return -1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    if (bind(fd, (struct sockaddr *)&addr, sizeof addr) != 0 || listen(fd, KEYD_LISTEN_BACKLOG) != 0) {
        close(fd);
        return -1;
    }
    return fd;
}

static void serve(SSL_CTX *ctx, int fd, struct keyd_p11 *p, const struct keyd_config *cfg)
{
    struct timeval tv = { .tv_sec = KEYD_IDLE_TIMEOUT_S, .tv_usec = 0 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);

    struct keyd_conn *c = keyd_conn_accept(ctx, fd);
    if (c == NULL)
        return;
    struct keyd_session s = { .peer = keyd_conn_peer(c), .p11 = p, .cfg = cfg };
    s.role = keyd_role_for_peer(s.peer);
    if (s.role == ROLE_NONE) {
        log_warn("listener: %s has no role here", s.peer);
        keyd_conn_close(c);
        return;
    }

    size_t cap = (size_t)cfg->max_request_kb * 1024;
    char *line = malloc(cap + 1);
    size_t reply_cap = 2 * cap + 256;
    char *reply = malloc(reply_cap);
    size_t used = 0;
    while (line != NULL && reply != NULL && !stopping) {
        size_t got = 0;
        if (used == cap) {
            log_warn("listener: request from %s too long", s.peer);
            break;
        }
        if (keyd_conn_read(c, line + used, cap - used, &got) != KEYD_OK)
            break;
        used += got;
        char *nl;
        while ((nl = memchr(line, '\n', used)) != NULL) {
            size_t len = (size_t)(nl - line) + 1;
            line[len - 1] = '\0';
            int n = keyd_handle_line(&s, line, reply, reply_cap);
            if (n < 0 || keyd_conn_write(c, reply, (size_t)n) != KEYD_OK)
                goto done;
            memmove(line, line + len, used - len);
            used -= len;
        }
    }
done:
    crypto_wipe(line, line ? cap : 0);
    free(line);
    free(reply);
    keyd_session_end(&s);
    keyd_conn_close(c);
    keyd_audit_flush();
}

int main(int argc, char **argv)
{
    static const struct option LONG_OPTS[] = {
        { "config", required_argument, NULL, 'c' },
        { "foreground", no_argument, NULL, 'f' },
        { "self-check", no_argument, NULL, 'S' },
        { "version", no_argument, NULL, 'V' },
        { "help", no_argument, NULL, 'h' },
        { NULL, 0, NULL, 0 },
    };
    const char *config_path = KEYD_CONFIG_FILE;
    int opt;

    while ((opt = getopt_long(argc, argv, "c:fh", LONG_OPTS, NULL)) != -1) {
        switch (opt) {
        case 'c':
            config_path = optarg;
            break;
        case 'f':
            break;
        case 'S':
            return keyd_self_check();
        case 'V':
            printf("tbkeyd %s\n", KEYD_VERSION);
            return 0;
        case 'h':
            usage(stdout);
            return 0;
        default:
            usage(stderr);
            return 2;
        }
    }

    struct keyd_config cfg;
    char err[256];
    if (keyd_config_load(&cfg, config_path, err, sizeof err) != KEYD_OK) {
        fprintf(stderr, "tbkeyd: %s\n", err);
        return 1;
    }
    enum keyd_log_level level = KEYD_LOG_INFO;
    keyd_log_level_parse(cfg.log_level, &level);
    keyd_log_open("tbkeyd", level, cfg.use_syslog);

    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = on_signal;
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGINT, &sa, NULL);
    signal(SIGPIPE, SIG_IGN);

    struct keyd_p11 p11;
    memset(&p11, 0, sizeof p11);
    int rc = keyd_rng_init();
    if (rc == KEYD_OK)
        rc = keyd_link_init();
    if (rc == KEYD_OK)
        rc = keyd_handheld_init();
    if (rc == KEYD_OK)
        rc = open_audit();
    if (rc == KEYD_OK)
        rc = open_partition(&p11, &cfg);
    if (rc == KEYD_OK && keyd_receipt_key_load(KEYD_SECRETS_DIR "/receipt-signing.pem") == KEYD_ERR_NOTFOUND)
        rc = keyd_receipt_key_rotate(KEYD_SECRETS_DIR "/receipt-signing.pem");
    if (rc != KEYD_OK) {
        log_err("start-up failed: %s", keyd_status_str(rc));
        return 1;
    }

    SSL_CTX *ctx = keyd_tls_server_new(1);
    int lfd = ctx ? listen_socket(&cfg) : -1;
    if (lfd < 0) {
        log_err("start-up: cannot listen on %s:%u: %s", cfg.listen_addr, (unsigned)cfg.listen_port, strerror(errno));
        return 1;
    }
    keyd_audit_append("tbkeyd", "start", "version %s", KEYD_VERSION);
    log_info("tbkeyd %s listening on %s:%u", KEYD_VERSION, cfg.listen_addr, (unsigned)cfg.listen_port);

    while (!stopping) {
        int fd = accept4(lfd, NULL, NULL, SOCK_CLOEXEC);
        if (fd < 0) {
            if (errno == EINTR)
                continue;
            log_warn("listener: accept failed: %s", strerror(errno));
            continue;
        }
        serve(ctx, fd, &p11, &cfg);
        keyd_tech_expire(time(NULL));
    }

    log_info("tbkeyd stopping");
    keyd_audit_append("tbkeyd", "stop", "signal");
    close(lfd);
    SSL_CTX_free(ctx);
    keyd_p11_close(&p11);
    keyd_receipt_key_free();
    keyd_audit_close();
    keyd_link_shutdown();
    keyd_rng_free();
    return 0;
}
