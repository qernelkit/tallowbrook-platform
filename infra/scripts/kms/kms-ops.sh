#!/usr/bin/env bash
# Small KMS tasks the platform team runs by hand or from CI:
#   sign-manifest <file>      sign a release manifest with the attestation key
#   export-data-key <out>     new data key for a partner export (plaintext + wrapped)
#   sign-test-webhook <file>  tag a sample webhook body, for partner onboarding
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly SCRIPT_DIR
# shellcheck source-path=SCRIPTDIR source=../lib/crypto-utils.sh
source "$SCRIPT_DIR/../lib/crypto-utils.sh"

readonly SIGNING_ALG="${SIGNING_ALG:-ML_DSA_SHAKE_256}"

usage() {
  echo "usage: $(basename "$0") sign-manifest <file> | export-data-key <out.json> | sign-test-webhook <file>"
}

sign_manifest() {
  local manifest=$1
  [[ $(wc -c < "$manifest") -le 4096 ]] || die "manifest too large for a RAW signature; sign its index instead"
  aws kms sign --key-id alias/tb-release-attestation \
    --message-type RAW \
    --message "fileb://${manifest}" \
    --signing-algorithm "$SIGNING_ALG" \
    --output text --query Signature | base64 -d > "${manifest}.sig"
  log_info "signature written to ${manifest}.sig"
}

new_export_data_key() {
  local out=$1
  aws kms generate-data-key --key-id alias/tb-exports \
    --key-spec AES_256 \
    --output json > "$out"
  chmod 0600 "$out"
  log_info "data key written to $out; delete it after the export job picks it up"
}

sign_test_webhook() {
  local payload=$1
  aws kms generate-mac --key-id alias/tb-webhook-mac \
    --mac-algorithm HMAC_SHA_256 \
    --message "fileb://${payload}" \
    --output text --query Mac
}

main() {
  [[ $# -eq 2 ]] || { usage; exit 2; }
  require_tools aws
  case "$1" in
    sign-manifest) sign_manifest "$2" ;;
    export-data-key) new_export_data_key "$2" ;;
    sign-test-webhook) sign_test_webhook "$2" ;;
    *) usage; exit 2 ;;
  esac
}

main "$@"
