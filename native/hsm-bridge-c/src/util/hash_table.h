/* Small chained hash table for in-memory caches, and an interning pool for operator names. */
#ifndef KEYD_UTIL_HASH_TABLE_H
#define KEYD_UTIL_HASH_TABLE_H

#include <stddef.h>
#include <stdint.h>

struct keyd_table_entry {
    char *key;
    void *value;
    uint64_t hash;
    struct keyd_table_entry *next;
};

struct keyd_table {
    struct keyd_table_entry **slots;
    size_t nslots;
    size_t count;
};

int keyd_table_init(struct keyd_table *t, size_t nslots);
void *keyd_table_get(const struct keyd_table *t, const char *key);
int keyd_table_put(struct keyd_table *t, const char *key, void *value);
void *keyd_table_remove(struct keyd_table *t, const char *key);
void keyd_table_each(struct keyd_table *t, int (*fn)(const char *key, void *value, void *arg), void *arg);
void keyd_table_free(struct keyd_table *t, void (*free_value)(void *));

const char *keyd_intern(const char *name);
void keyd_intern_reset(void);

#endif
