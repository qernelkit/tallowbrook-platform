/*
 * gwfw: the depot gateway firmware main loop. Uplinks telemetry over TLS 1.3, seals records, verifies
 * signed updates, services the LTE auth requests from the small cells, and feeds a watchdog.
 *
 * The real product boots from the stage-1 loader in boot/; here main() runs on Linux user space.
 */
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "gateway/gw.h"
#include "gateway/gw_config.h"
#include "gateway/gw_log.h"
#include "gateway/telemetry.h"

static volatile sig_atomic_t running = 1;

static void on_term(int sig)
{
    (void)sig;
    running = 0;
}

int gw_entropy_init(void);
void gw_entropy_free(void);
int gw_device_identity_load_or_create(void);
int gw_heartbeat_tick(uint32_t uptime_s);
void gw_hss_poll(void);

static void watchdog_pet(void)
{
    /* The product writes to /dev/watchdog; on the host this is a no-op. */
}

int main(void)
{
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = on_term;
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGINT, &sa, NULL);

    if (gw_entropy_init() != GW_OK) {
        GW_LOG_ERR("entropy: init failed");
        return 1;
    }
    if (gw_device_identity_load_or_create() != GW_OK) {
        GW_LOG_ERR("identity: no device key");
        gw_entropy_free();
        return 1;
    }
    GW_LOG("gwfw up on %s:%d", GW_UPLINK_HOST, GW_UPLINK_PORT);

    uint32_t uptime = 0;
    while (running) {
        watchdog_pet();
        gw_hss_poll();
        if (uptime % GW_HEARTBEAT_INTERVAL_S == 0)
            gw_heartbeat_tick(uptime);
        sleep(1);
        uptime++;
    }
    GW_LOG("gwfw stopping after %us", uptime);
    gw_entropy_free();
    return 0;
}
