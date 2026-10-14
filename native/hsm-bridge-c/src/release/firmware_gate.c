/*
 * Gateway firmware releases. Before a release is staged to the depots, tbkeyd checks the release
 * signature against the firmware root that the gateways themselves trust (the same certificate is
 * burned into stage 1). Releases are signed directly by the root key, offline, by the release
 * managers.
 *
 * A release directory holds "<version>/gwfw.img" and "<version>/gwfw.img.sig".
 */
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "keyd/crypto_api.h"
#include "keyd/keyd.h"
#include "util/log.h"

#define RELEASE_IMAGE_MAX (64u << 20)
#define RELEASE_SIG_MAX (16u << 10)

static const char FIRMWARE_ROOT_PEM[] =
    "-----BEGIN CERTIFICATE-----\n"
    "MIIgLjCCAWigAwIBAgIFAPHgAAEwCwYJYIZIAWUDBAMUMFkxCzAJBgNVBAYTAlVT\n"
    "MR4wHAYDVQQKDBVUYWxsb3dicm9vayBMb2dpc3RpY3MxKjAoBgNVBAMMIVRhbGxv\n"
    "d2Jyb29rIEdhdGV3YXkgRmlybXdhcmUgUm9vdDAeFw0yNjAxMDEwMDAwMDBaFw00\n"
    "NjAxMDEwMDAwMDBaMFkxCzAJBgNVBAYTAlVTMR4wHAYDVQQKDBVUYWxsb3dicm9v\n"
    "ayBMb2dpc3RpY3MxKjAoBgNVBAMMIVRhbGxvd2Jyb29rIEdhdGV3YXkgRmlybXdh\n"
    "cmUgUm9vdDAwMAsGCWCGSAFlAwQDFAMhAMz8gMD/PxH5p3KqfXiZB7W6V1yTcP6G\n"
    "tAZQ19amF2JTo0UwQzAdBgNVHQ4EFgQU4F9/emIsVM5IVEqBOQtd/7WcUUMwEgYD\n"
    "VR0TAQH/BAgwBgEB/wIBADAOBgNVHQ8BAf8EBAMCAgQwCwYJYIZIAWUDBAMUA4Ie\n"
    "sQB62U7i9HsVpp+9y/QY0o96opEj55rs8ZKCJDL8LAGt4e6V2XovisnLerSCqKJb\n"
    "UjDKgmJMsCOD4ghj51x++BnrSbqOYX0Wf+aCqKK7jniYlgkD79Fcm5aYe00Ik5LZ\n"
    "u8K156vndrPqgAdJ/zqDkVRL+5AzVktro8M1iUcLDHEk35f5IjGZFddFfqWA8g3I\n"
    "buLr4/rPIkl0ZjfO7QjnRFVyKX7Via+oHWMd9+fXbw7hSrfPdJeSnFe9AgQsjxYU\n"
    "VqVboJtUdz6sDk+a5W2XGSj8NMFcHPanZ/NkENto5bhzjIi8lryY8u1HAiY8R2fk\n"
    "FRHDuzIdQkxkNTk7hm4kb+C2xjTsiE4P+R6phU1QswnPelvKDatVlyhxC1M645E+\n"
    "Y6TX0uQPAnuia1X9TrFfq2KzAP2kElbYogIOTfI7B74IdBuu8Cu+P1TKf+lu+i1X\n"
    "WMyW81MDLMD52eCD0mBenXDpHchxLQLhxC8Gc2/9FTTqb8DwUQWFfxxOBp6+Q79y\n"
    "6NTI/9LqTnWxZAzH9jO6YSx8l8ACHB2rrv13I2eHwurArR5RIjCZx03906VQI4im\n"
    "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\n"
    "-----END CERTIFICATE-----\n";

/* Operator-supplied chain files are split on this marker before each certificate is parsed. */
static const char PEM_END_MARKER[] = "-----END CERTIFICATE-----";

static X509 *release_root(void)
{
    static X509 *root;
    if (root != NULL)
        return root;
    BIO *bio = BIO_new_mem_buf(FIRMWARE_ROOT_PEM, -1);
    if (bio == NULL)
        return NULL;
    root = PEM_read_bio_X509(bio, NULL, NULL, NULL);
    BIO_free(bio);
    if (root == NULL)
        log_openssl_errors("release: embedded root");
    return root;
}

int keyd_release_root_ready(void)
{
    return release_root() != NULL ? KEYD_OK : KEYD_ERR_LIB;
}

static int valid_version(const char *v)
{
    size_t n = strlen(v);
    if (n == 0 || n >= sizeof((struct release *)0)->version)
        return 0;
    for (size_t i = 0; i < n; i++) {
        char c = v[i];
        if (!((c >= '0' && c <= '9') || c == '.' || c == '-' || (c >= 'a' && c <= 'z')))
            return 0;
    }
    return v[0] != '.';
}

int keyd_release_load(const char *dir, const char *version, struct release *rel)
{
    char path[512];
    struct keyd_buf img = { 0 }, sig = { 0 };
    int rc;

    memset(rel, 0, sizeof *rel);
    if (!valid_version(version))
        return KEYD_ERR_ARGS;
    snprintf(rel->version, sizeof rel->version, "%s", version);

    snprintf(path, sizeof path, "%s/%s/gwfw.img", dir, version);
    if ((rc = keyd_read_file(path, RELEASE_IMAGE_MAX, &img)) != KEYD_OK)
        goto fail;
    snprintf(path, sizeof path, "%s/%s/gwfw.img.sig", dir, version);
    if ((rc = keyd_read_file(path, RELEASE_SIG_MAX, &sig)) != KEYD_OK)
        goto fail;
    rel->image = img.data;
    rel->image_len = img.len;
    rel->sig = sig.data;
    rel->sig_len = sig.len;
    return KEYD_OK;
fail:
    log_warn("release %s: cannot read %s: %s", version, path, keyd_status_str(rc));
    keyd_buf_free(&img);
    keyd_buf_free(&sig);
    return rc;
}

void keyd_release_free(struct release *rel)
{
    free(rel->image);
    free(rel->sig);
    memset(rel, 0, sizeof *rel);
}

int keyd_release_check(const struct release *rel)
{
    X509 *root = release_root();
    if (root == NULL)
        return KEYD_ERR_LIB;

    EVP_PKEY_CTX *vctx = EVP_PKEY_CTX_new_from_pkey(NULL, X509_get0_pubkey(root), NULL);
    EVP_SIGNATURE *alg = EVP_SIGNATURE_fetch(NULL, "SLH-DSA-SHA2-128s", NULL);
    int ok = alg && vctx && EVP_PKEY_verify_message_init(vctx, alg, NULL) == 1 && EVP_PKEY_verify(vctx, rel->sig, rel->sig_len, rel->image, rel->image_len) == 1;
    if (ok)
        log_info("release %s: signature checked against the gateway root", rel->version);
    else
        log_warn("release %s: rejected, not signed by the gateway root", rel->version);
    EVP_PKEY_CTX_free(vctx);
    EVP_SIGNATURE_free(alg);
    return ok ? KEYD_OK : KEYD_ERR_AUTH;
}

/*
 * Release managers attach the chain they signed with. Staging refuses a release whose chain does not
 * start with our root, which catches a release signed by a lab key before it reaches a depot.
 */
int keyd_release_chain_matches(const char *chain_text)
{
    const char *end = strstr(chain_text, PEM_END_MARKER);
    if (end == NULL)
        return KEYD_ERR_ARGS;
    size_t first_len = (size_t)(end - chain_text) + strlen(PEM_END_MARKER);

    X509 *root = release_root();
    BIO *bio = BIO_new_mem_buf(chain_text, (int)first_len);
    X509 *first = bio ? PEM_read_bio_X509(bio, NULL, NULL, NULL) : NULL;
    int rc = root && first && X509_cmp(root, first) == 0 ? KEYD_OK : KEYD_ERR_POLICY;
    X509_free(first);
    BIO_free(bio);
    return rc;
}
