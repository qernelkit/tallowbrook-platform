/* File system layout. Packaging creates the directories; the PKI repository provisions /etc/tallowbrook/pki. */
#ifndef KEYD_PATHS_H
#define KEYD_PATHS_H

#define KEYD_CONFIG_FILE "/etc/tallowbrook/keyd.conf"
#define KEYD_STATE_DIR "/var/lib/tbkeyd"
#define KEYD_RUN_DIR "/run/tbkeyd"
#define KEYD_PID_FILE KEYD_RUN_DIR "/tbkeyd.pid"

/* Listener identity, and the CA that issues the client certificates we accept. */
#define KEYD_TLS_CERT_FILE "/etc/tallowbrook/pki/services/api.crt"
#define KEYD_TLS_KEY_FILE "/etc/tallowbrook/pki/services/api.key"
#define KEYD_CLIENT_CA_FILE "/etc/tallowbrook/pki/ca/issuing-ec.crt"

/* Archive key material. */
#define KEYD_ARCHIVE_KEK_FILE "/etc/tallowbrook/pki/keys/archive-kek-mlkem768.pem"
#define KEYD_ESCROW_PUB_FILE "/etc/tallowbrook/pki/keys/escrow-mlkem1024.pub.pem"
#define KEYD_ESCROW_SECONDARY_FILE KEYD_STATE_DIR "/escrow/secondary.pub"

/* Operator console. */
#define KEYD_OPERATORS_FILE KEYD_STATE_DIR "/console/operators"
#define KEYD_VAULT_FILE KEYD_STATE_DIR "/console/pin.vault"
#define KEYD_TOKEN_MODULE "/usr/lib/aarch64-linux-gnu/opensc-pkcs11.so"

/* Secrets tbkeyd owns, one file each, mode 0600. */
#define KEYD_SECRETS_DIR KEYD_STATE_DIR "/secrets"
#define KEYD_PARTNER_DIR KEYD_STATE_DIR "/partners"

#define KEYD_AUDIT_DIR "/var/log/tbkeyd/audit"
#define KEYD_SPOOL_DIR "/var/spool/tbkeyd"
#define KEYD_RELEASE_DIR "/srv/releases/gateway"

#endif
