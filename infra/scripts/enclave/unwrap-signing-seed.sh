#!/usr/bin/env bash
# Parent-instance side of the signing enclave start-up: asks KMS to re-wrap the
# sealed signing seed to the enclave's attested key. The output can only be
# opened inside the enclave whose measurements match the key policy.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly SCRIPT_DIR
# shellcheck source-path=SCRIPTDIR source=../lib/crypto-utils.sh
source "$SCRIPT_DIR/../lib/crypto-utils.sh"

readonly SEALED_SEED="${SEALED_SEED:-/var/lib/signing-enclave/seed.sealed}"

usage() {
  echo "usage: $(basename "$0") <attestation-document> <out-dir>"
}

main() {
  [[ $# -eq 2 ]] || { usage; exit 2; }
  local ATTESTATION_DOC=$1 out=$2
  require_tools aws
  [[ -s "$ATTESTATION_DOC" ]] || die "empty attestation document: $ATTESTATION_DOC"
  mkdir -p "$out"

  aws kms decrypt --ciphertext-blob "fileb://${SEALED_SEED}" \
    --key-id alias/tb-enclave-seed \
    --recipient "KeyEncryptionAlgorithm=RSAES_OAEP_SHA_256,AttestationDocument=fileb://${ATTESTATION_DOC}" \
    --output text --query CiphertextForRecipient \
    | base64 -d > "$out/seed.cms"
  log_info "re-wrapped seed at $out/seed.cms; hand it to the enclave over vsock"
}

main "$@"
