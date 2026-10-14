#!/usr/bin/env bash
# Generates the key-agreement pair used for remote key loading to the depot
# PIN pads, inside the payments CloudHSM cluster. Run from the HSM client host.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly SCRIPT_DIR
# shellcheck source-path=SCRIPTDIR source=../lib/crypto-utils.sh
source "$SCRIPT_DIR/../lib/crypto-utils.sh"

readonly MODULE=/opt/cloudhsm/lib/libcloudhsm_pkcs11.so

usage() {
  echo "usage: $(basename "$0") <label> <hex-id>   (needs CU_LOGIN=user:password)"
}

main() {
  [[ $# -eq 2 ]] || { usage; exit 2; }
  local label=$1 id=$2
  [[ "$id" =~ ^[0-9a-f]+$ ]] || die "id must be lower-case hex"
  require_env CU_LOGIN
  require_tools pkcs11-tool

  pkcs11-tool --module "$MODULE" --login --pin "$CU_LOGIN" \
    --keypairgen --key-type EC:secp384r1 \
    --label "$label" --id "$id" --usage-derive
  pkcs11-tool --module "$MODULE" --login --pin "$CU_LOGIN" --list-objects --type pubkey --label "$label"
  log_info "key pair ${label} created; record the id ${id} in the PIN pad loading sheet"
}

main "$@"
