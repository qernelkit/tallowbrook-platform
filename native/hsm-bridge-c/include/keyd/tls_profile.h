/*
 * Listener profile for the key custody port. Depot gateways, the platform services and the
 * fuel-card back office connect here.
 */
#ifndef KEYD_LISTENER_PROFILE_H
#define KEYD_LISTENER_PROFILE_H

/* Key exchange groups, most preferred first. The same variable in the environment overrides
 * this on one host while a client is being upgraded. */
#define KEYD_TLS_GROUPS "X25519MLKEM768:X25519"

/* The fuel-card back office still connects with 1.2; it only gets these suites. */
#define KEYD_TLS12_CIPHERS "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305"

#define KEYD_LISTEN_PORT 7443
#define KEYD_LISTEN_BACKLOG 64
#define KEYD_IDLE_TIMEOUT_S 30

#endif
