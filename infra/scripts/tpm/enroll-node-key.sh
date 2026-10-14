#!/usr/bin/env bash
# Creates the node attestation key in the TPM and exports its public half for
# enrolment with the fleet registry. Run once per node during provisioning.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly SCRIPT_DIR
# shellcheck source-path=SCRIPTDIR source=../lib/crypto-utils.sh
source "$SCRIPT_DIR/../lib/crypto-utils.sh"

readonly PERSISTENT_HANDLE="0x81010002"
readonly OUT_DIR="${OUT_DIR:-/var/lib/node-enrolment}"

usage() {
  echo "usage: $(basename "$0")   (writes ${OUT_DIR}/node-attest.pub.pem)"
}

main() {
  [[ "${1:-}" == "-h" ]] && { usage; exit 0; }
  require_tools tpm2_createprimary tpm2_create tpm2_load tpm2_evictcontrol tpm2_readpublic
  local ctx
  ctx=$(mktemp -d)
  trap 'rm -rf "$ctx"' EXIT
  mkdir -p "$OUT_DIR"

  tpm2_createprimary -C o -G ecc384 -c "$ctx/primary.ctx"
  tpm2_create -C "$ctx/primary.ctx" -G rsa3072:rsassa-sha384 \
    -u "$ctx/node.pub" -r "$ctx/node.priv" \
    -a "fixedtpm|fixedparent|sensitivedataorigin|userwithauth|sign"
  tpm2_load -C "$ctx/primary.ctx" -u "$ctx/node.pub" -r "$ctx/node.priv" -c "$ctx/node.ctx"
  tpm2_evictcontrol -C o -c "$ctx/node.ctx" "$PERSISTENT_HANDLE"
  tpm2_readpublic -c "$PERSISTENT_HANDLE" -f pem -o "$OUT_DIR/node-attest.pub.pem"

  log_info "attestation key persisted at ${PERSISTENT_HANDLE}; upload ${OUT_DIR}/node-attest.pub.pem"
}

main "$@"
