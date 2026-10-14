/*
 * The handle cache maps object labels to PKCS#11 handles so a request does not need a
 * C_FindObjects round trip each time; it is keyed with FNV-1a. Operator names are interned once per
 * login so audit records can point at them; that pool uses djb2. Neither table holds secrets.
 */
#include "util/hash_table.h"

#include <stdlib.h>
#include <string.h>

#include "keyd/keyd.h"

static uint64_t fnv1a(const char *s)
{
    uint64_t h = 0xcbf29ce484222325ULL;
    const unsigned char *p = (const unsigned char *)s;

    while (*p)
        h = (h ^ *p++) * 0x100000001b3ULL;
    return h;
}

int keyd_table_init(struct keyd_table *t, size_t nslots)
{
    t->slots = calloc(nslots, sizeof *t->slots);
    if (t->slots == NULL)
        return KEYD_ERR_NOMEM;
    t->nslots = nslots;
    t->count = 0;
    return KEYD_OK;
}

static struct keyd_table_entry **find_slot(const struct keyd_table *t, const char *key, uint64_t h)
{
    struct keyd_table_entry **pp = &t->slots[h % t->nslots];

    while (*pp != NULL && ((*pp)->hash != h || strcmp((*pp)->key, key) != 0))
        pp = &(*pp)->next;
    return pp;
}

void *keyd_table_get(const struct keyd_table *t, const char *key)
{
    if (t->slots == NULL)
        return NULL;
    struct keyd_table_entry **pp = find_slot(t, key, fnv1a(key));
    return *pp ? (*pp)->value : NULL;
}

int keyd_table_put(struct keyd_table *t, const char *key, void *value)
{
    uint64_t h = fnv1a(key);
    struct keyd_table_entry **pp = find_slot(t, key, h);

    if (*pp != NULL) {
        (*pp)->value = value;
        return KEYD_OK;
    }
    struct keyd_table_entry *e = calloc(1, sizeof *e);
    if (e == NULL)
        return KEYD_ERR_NOMEM;
    e->key = strdup(key);
    if (e->key == NULL) {
        free(e);
        return KEYD_ERR_NOMEM;
    }
    e->value = value;
    e->hash = h;
    *pp = e;
    t->count++;
    return KEYD_OK;
}

void *keyd_table_remove(struct keyd_table *t, const char *key)
{
    if (t->slots == NULL)
        return NULL;
    struct keyd_table_entry **pp = find_slot(t, key, fnv1a(key));
    struct keyd_table_entry *e = *pp;
    if (e == NULL)
        return NULL;
    void *value = e->value;
    *pp = e->next;
    free(e->key);
    free(e);
    t->count--;
    return value;
}

void keyd_table_each(struct keyd_table *t, int (*fn)(const char *key, void *value, void *arg), void *arg)
{
    for (size_t i = 0; i < t->nslots; i++) {
        struct keyd_table_entry *e = t->slots[i];
        while (e != NULL) {
            struct keyd_table_entry *next = e->next;
            if (fn(e->key, e->value, arg) != 0)
                return;
            e = next;
        }
    }
}

void keyd_table_free(struct keyd_table *t, void (*free_value)(void *))
{
    for (size_t i = 0; i < t->nslots; i++) {
        struct keyd_table_entry *e = t->slots[i];
        while (e != NULL) {
            struct keyd_table_entry *next = e->next;
            if (free_value != NULL)
                free_value(e->value);
            free(e->key);
            free(e);
            e = next;
        }
    }
    free(t->slots);
    t->slots = NULL;
    t->nslots = 0;
    t->count = 0;
}

/* ---- interning */

#define INTERN_SLOTS 64

struct intern_entry {
    struct intern_entry *next;
    char name[];
};

static struct intern_entry *intern_pool[INTERN_SLOTS];

static unsigned long djb2(const char *s)
{
    unsigned long h = 5381;
    int c;

    while ((c = *s++) != 0)
        h = ((h << 5) + h) + (unsigned char)c;
    return h;
}

const char *keyd_intern(const char *name)
{
    unsigned long slot = djb2(name) % INTERN_SLOTS;

    for (struct intern_entry *e = intern_pool[slot]; e != NULL; e = e->next) {
        if (strcmp(e->name, name) == 0)
            return e->name;
    }
    size_t n = strlen(name);
    struct intern_entry *e = malloc(sizeof *e + n + 1);
    if (e == NULL)
        return NULL;
    memcpy(e->name, name, n + 1);
    e->next = intern_pool[slot];
    intern_pool[slot] = e;
    return e->name;
}

void keyd_intern_reset(void)
{
    for (size_t i = 0; i < INTERN_SLOTS; i++) {
        struct intern_entry *e = intern_pool[i];
        while (e != NULL) {
            struct intern_entry *next = e->next;
            free(e);
            e = next;
        }
        intern_pool[i] = NULL;
    }
}
