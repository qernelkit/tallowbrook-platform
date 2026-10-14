/*
 * Algorithm names shared across tbkeyd. Changing one of these changes what the depot gateways and
 * the receipt verifiers in billing must accept, so coordinate a change with those teams first.
 */
#ifndef KEYD_ALGORITHMS_H
#define KEYD_ALGORITHMS_H

/* Key encapsulation the depot gateways use when the bridge rotates their link key. */
#define KEYD_DEPOT_KEM "ML-KEM-768"

/* Digest behind the depot link key schedule. */
#define KEYD_LINK_KDF_DIGEST "SHA256"

/* Delivery receipts; billing verifies with the same name. */
#define KEYD_RECEIPT_SIG_ALG "ML-DSA-65"

/* Frame layer sizes the gateways depend on. */
#define KEYD_LINK_KEY_LEN 32
#define KEYD_LINK_IV_LEN 12
#define KEYD_LINK_TAG_LEN 16
#define KEYD_LINK_HELLO_LEN 32

#endif
