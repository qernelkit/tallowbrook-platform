#include <string.h>

#include "config/config.h"
#include "keyd/keyd.h"
#include "test.h"

static const char GOOD[] = "# depot north\n"
                           "listen_addr = 10.20.0.5\n"
                           "listen_port = 7443\n"
                           "p11_module = /usr/lib/hsm/libvendor.so\n"
                           "p11_slot_label = tbk-prod\n"
                           "log_level = debug\n"
                           "syslog = yes\n"
                           "archive_agent = 127.0.0.1:9090\n";

TEST(config_parses_known_settings)
{
    struct keyd_config cfg;
    char err[128] = "";
    keyd_config_defaults(&cfg);
    CHECK(keyd_config_parse(&cfg, GOOD, strlen(GOOD), err, sizeof err) == KEYD_OK);
    CHECK(strcmp(cfg.listen_addr, "10.20.0.5") == 0);
    CHECK(cfg.listen_port == 7443);
    CHECK(strcmp(cfg.p11_slot_label, "tbk-prod") == 0);
    CHECK(cfg.use_syslog == 1);
    CHECK(strcmp(cfg.agent_host, "127.0.0.1") == 0);
    CHECK(cfg.agent_port == 9090);
}

TEST(config_rejects_unknown_settings)
{
    struct keyd_config cfg;
    char err[128] = "";
    const char text[] = "p11_module = /x.so\np11_slot_label = a\ncolour = blue\n";
    keyd_config_defaults(&cfg);
    CHECK(keyd_config_parse(&cfg, text, strlen(text), err, sizeof err) == KEYD_ERR_ARGS);
    CHECK(strstr(err, "line 3") != NULL);
}

TEST(config_rejects_bad_ports)
{
    struct keyd_config cfg;
    char err[128] = "";
    const char text[] = "p11_module = /x.so\np11_slot_label = a\nlisten_port = 70000\n";
    keyd_config_defaults(&cfg);
    CHECK(keyd_config_parse(&cfg, text, strlen(text), err, sizeof err) == KEYD_ERR_ARGS);
}

TEST(config_requires_the_partition)
{
    struct keyd_config cfg;
    char err[128] = "";
    const char text[] = "listen_port = 7443\n";
    keyd_config_defaults(&cfg);
    CHECK(keyd_config_parse(&cfg, text, strlen(text), err, sizeof err) == KEYD_ERR_ARGS);
}
