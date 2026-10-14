#!/usr/bin/env bash
# Creates the transit keys the services expect. Safe to re-run: existing keys
# are left alone (rotation is a separate runbook).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly SCRIPT_DIR
# shellcheck source-path=SCRIPTDIR source=../lib/crypto-utils.sh
source "$SCRIPT_DIR/../lib/crypto-utils.sh"

# key name -> creation parameters
declare -A TRANSIT_KEYS=(
  [ledger-export]="type=aes256-gcm96"
  [invoice-sign]="type=ecdsa-p384"
  [journal-batch]="type=ml-dsa parameter_set=87"
)

usage() {
  echo "usage: $(basename "$0")   (needs VAULT_ADDR and a token with the platform-admin policy)"
}

main() {
  [[ "${1:-}" == "-h" ]] && { usage; exit 0; }
  require_tools vault
  require_env VAULT_ADDR

  vault secrets list -format=json | jq -e '."transit/"' >/dev/null ||
    vault secrets enable -path=transit transit

  local name
  for name in "${!TRANSIT_KEYS[@]}"; do
    if vault read -format=json "transit/keys/${name}" >/dev/null 2>&1; then
      note_unchanged "$name"
      continue
    fi
    # shellcheck disable=SC2086 # the parameters are deliberately split into words
    vault write -f "transit/keys/${name}" ${TRANSIT_KEYS[$name]}
    vault write "transit/keys/${name}/config" deletion_allowed=false exportable=false
    log_info "created transit key ${name}"
  done
}

main "$@"
