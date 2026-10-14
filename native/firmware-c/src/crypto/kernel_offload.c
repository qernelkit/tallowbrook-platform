/*
 * Bulk AEAD and hashing are offloaded to the SoC crypto engine through the Linux kernel crypto API
 * (AF_ALG). The gateway uses this for sealing large telemetry spools and hashing update images,
 * where the engine is much faster than the CPU.
 */
#define _GNU_SOURCE
#include <linux/if_alg.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "gateway/gw.h"
#include "gateway/gw_log.h"

static const struct sockaddr_alg AEAD_ADDR = {
    .salg_family = AF_ALG,
    .salg_type = "aead",
    .salg_name = "gcm(aes)",
};

static const struct sockaddr_alg HASH_ADDR = {
    .salg_family = AF_ALG,
    .salg_type = "hash",
    .salg_name = "sha256",
};

static int alg_socket(const struct sockaddr_alg *addr)
{
    int fd = socket(AF_ALG, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
    if (fd < 0)
        return -1;
    if (bind(fd, (const struct sockaddr *)addr, sizeof *addr) != 0) {
        close(fd);
        return -1;
    }
    return fd;
}

int gw_offload_aead_available(void)
{
    int fd = alg_socket(&AEAD_ADDR);
    if (fd < 0)
        return GW_ERR_IO;
    close(fd);
    return GW_OK;
}

int gw_offload_hash(const uint8_t *data, size_t len, uint8_t digest[32])
{
    int tfm = alg_socket(&HASH_ADDR);
    if (tfm < 0)
        return GW_ERR_IO;
    int op = accept4(tfm, NULL, NULL, SOCK_CLOEXEC);
    int rc = GW_ERR_IO;
    if (op >= 0 && send(op, data, len, 0) == (ssize_t)len && read(op, digest, 32) == 32)
        rc = GW_OK;
    if (op >= 0)
        close(op);
    close(tfm);
    return rc;
}
