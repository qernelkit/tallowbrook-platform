#!/usr/bin/env bash
# One-time setup of the Vault PKI mount that issues internal service
# certificates (role internal-services).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly SCRIPT_DIR
# shellcheck source-path=SCRIPTDIR source=../lib/crypto-utils.sh
source "$SCRIPT_DIR/../lib/crypto-utils.sh"

readonly PAYLOADS="$SCRIPT_DIR/payloads"
readonly OUT_DIR="${OUT_DIR:-$PWD}"

usage() {
  echo "usage: $(basename "$0")   (needs VAULT_ADDR and a token with the platform-admin policy)"
}

main() {
  [[ "${1:-}" == "-h" ]] && { usage; exit 0; }
  require_tools vault jq
  require_env VAULT_ADDR

  vault secrets enable -path=pki pki
  vault secrets tune -max-lease-ttl=87600h pki

  vault write -format=json pki/root/generate/internal @"${PAYLOADS}/root-ca.json" \
    | jq -r '.data.certificate' > "${OUT_DIR}/vault-root-ca.pem"
  vault write pki/roles/internal-services @"${PAYLOADS}/role-internal-services.json"
  vault write pki/config/urls \
    issuing_certificates="https://vault.internal.tallowbrook.example:8200/v1/pki/ca" \
    crl_distribution_points="https://vault.internal.tallowbrook.example:8200/v1/pki/crl"

  log_info "PKI mount ready; publish ${OUT_DIR}/vault-root-ca.pem to the trust bundle repo"
}

main "$@"
