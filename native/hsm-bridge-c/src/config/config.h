/* keyd.conf: "name = value" lines, '#' comments. */
#ifndef KEYD_CONFIG_H
#define KEYD_CONFIG_H

#include <stddef.h>

struct keyd_config {
    char listen_addr[64];
    unsigned short listen_port;
    char p11_module[256];
    char p11_slot_label[33];
    char card_module[256];
    char log_level[16];
    int use_syslog;
    char agent_host[64];
    unsigned short agent_port;
    char release_dir[256];
    unsigned int max_request_kb;
};

void keyd_config_defaults(struct keyd_config *cfg);
int keyd_config_parse(struct keyd_config *cfg, const char *text, size_t len, char *err, size_t err_cap);
int keyd_config_load(struct keyd_config *cfg, const char *path, char *err, size_t err_cap);

#endif
