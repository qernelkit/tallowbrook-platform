#!/usr/bin/env bash
# Prepares an on-call engineer's YubiKey: signing key in PIV slot 9c, then the
# certificate the PKI team issues for it.
#   generate <engineer>          make the key and write <engineer>.pub.pem
#   import <engineer> <cert.pem> load the issued certificate into slot 9c
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly SCRIPT_DIR
# shellcheck source-path=SCRIPTDIR source=../lib/crypto-utils.sh
source "$SCRIPT_DIR/../lib/crypto-utils.sh"

usage() {
  echo "usage: $(basename "$0") generate <engineer> | import <engineer> <cert.pem>"
}

main() {
  [[ $# -ge 2 ]] || { usage; exit 2; }
  require_tools ykman
  local engineer=$2 pubkey="${2}.pub.pem"
  ykman piv info
  case "$1" in
    generate)
      confirm "Generate a new key in slot 9c for ${engineer}?" || exit 1
      ykman piv keys generate --algorithm ECCP384 --pin-policy ONCE --touch-policy CACHED 9c "$pubkey"
      log_info "send ${pubkey} to PKI with the on-call request for ${engineer}"
      ;;
    import)
      [[ $# -eq 3 ]] || { usage; exit 2; }
      ykman piv certificates import 9c "$3"
      log_info "slot 9c ready for ${engineer}"
      ;;
    *) usage; exit 2 ;;
  esac
}

main "$@"
