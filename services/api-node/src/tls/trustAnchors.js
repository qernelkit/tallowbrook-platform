// The internal root the gateway trusts for payments and ledger. It is pinned here
// rather than read from the host store, so a base-image change cannot widen it.
export const TALLOWBROOK_ROOT_E2 = `-----BEGIN CERTIFICATE-----
MIICEDCCAZagAwIBAgIEbiAkoTAKBggqhkjOPQQDAzBOMQswCQYDVQQGEwJVUzEeMBwGA1UECgwV
VGFsbG93YnJvb2sgTG9naXN0aWNzMR8wHQYDVQQDDBZUYWxsb3dicm9vayBSb290IENBIEUyMB4X
DTI0MDEwMTAwMDAwMFoXDTQ0MDEwMTAwMDAwMFowTjELMAkGA1UEBhMCVVMxHjAcBgNVBAoMFVRh
bGxvd2Jyb29rIExvZ2lzdGljczEfMB0GA1UEAwwWVGFsbG93YnJvb2sgUm9vdCBDQSBFMjB2MBAG
ByqGSM49AgEGBSuBBAAiA2IABI+2Tq7AMC09yg0J4d97f0Vhkn0n97PY6RBnnVYj2DLOtOVwo3UE
oQvJsMN5cp18TlESwILP0LprAgVMuYDFu3F6Jrq6sGtViI9v0Qop9PgaVt7l4eyUSg2uqtc49+/a
pKNFMEMwHQYDVR0OBBYEFIOMaNvY/dK19h71amQbGSMWAZ3OMBIGA1UdEwEB/wQIMAYBAf8CAQEw
DgYDVR0PAQH/BAQDAgEGMAoGCCqGSM49BAMDA2gAMGUCMQDkoL6qKV+FZ4oAi+vMPi9d5gGvaoPr
hWVSG54IPb1cmpLfiLiIUujUaYaqnhKbj/MCMGbAMrjcOUMMNwSVEcXOudLmb6Sd9WJL21iG/5kc
BXrIGS8eQD0UZ82KV5rOYCRlGQ==
-----END CERTIFICATE-----`;

const PEM_CERT_BLOCK = /-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/g;

/**
 * Splits an operator-supplied bundle (config.upstream.extraCaFile) into single
 * PEM blocks. Used during migrations, when a second root is trusted for a while.
 * @param {string} bundle
 * @returns {string[]}
 */
export function splitBundle(bundle) {
  return bundle.match(PEM_CERT_BLOCK) ?? [];
}
