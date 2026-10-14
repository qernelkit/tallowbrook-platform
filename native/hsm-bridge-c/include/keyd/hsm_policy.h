/*
 * Mechanism policy agreed with the HSM administrators. Only hsm_crypto.c includes this.
 */
#ifndef KEYD_TOKEN_POLICY_H
#define KEYD_TOKEN_POLICY_H

#include <p11-kit/pkcs11.h>

/* PKCS#11 3.0 defines the RFC 5649 wrap mechanism, but the p11-kit header we build against
 * stops at the 2.40 constant set. The value is the one in the OASIS 3.0 mechanism table. */
#ifndef CKM_AES_KEY_WRAP_KWP
#define CKM_AES_KEY_WRAP_KWP 0x0000210BUL
#endif

/* Data keys leave the HSM only wrapped by the KEK, and the partition allows one wrap mechanism. */
static const CK_MECHANISM_TYPE KEYD_WRAP_MECHANISM = CKM_AES_KEY_WRAP_KWP;

/* Largest wrapped blob we hand back (a 512-bit data key plus the wrap overhead). */
#define KEYD_WRAPPED_MAX 80

#endif
