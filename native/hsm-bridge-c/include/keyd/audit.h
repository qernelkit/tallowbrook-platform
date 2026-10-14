/* Chained audit records and the sealed segments shipped to the archive. */
#ifndef KEYD_AUDIT_H
#define KEYD_AUDIT_H

#include <stddef.h>
#include <stdint.h>
#include <time.h>

#define KEYD_AUDIT_TAG_LEN 64
#define KEYD_SEGMENT_KEY_LEN 32
#define KEYD_SEGMENT_MAX (1u << 20)

struct audit_record {
    uint64_t seq;
    time_t at;
    char actor[48];
    char action[32];
    char detail[160];
};

struct audit_segment {
    char id[40];
    unsigned char *data;
    size_t len;
    size_t cap;
    uint64_t first_seq;
    uint64_t last_seq;
};

int keyd_audit_open(const char *dir, const unsigned char *chain_key, size_t key_len);
int keyd_audit_append(const char *actor, const char *action, const char *fmt, ...)
    __attribute__((format(printf, 3, 4)));
int keyd_audit_append_record(struct audit_record *rec, unsigned char tag[KEYD_AUDIT_TAG_LEN]);
int keyd_audit_flush(void);
void keyd_audit_close(void);
uint64_t keyd_audit_last_seq(void);

int keyd_segment_seal(const struct audit_segment *seg, const unsigned char key[KEYD_SEGMENT_KEY_LEN],
                      unsigned char *out, size_t out_cap, size_t *out_len);
int keyd_segment_ship(const char *agent_host, unsigned short agent_port, const char *segment_id,
                      const unsigned char *body, size_t body_len);
int keyd_segment_spool(const char *segment_id, const unsigned char *body, size_t body_len);

#endif
