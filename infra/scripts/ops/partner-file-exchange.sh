#!/usr/bin/env bash
# File exchange with partners and carriers:
#   export   bundle a partner export directory for upload to their S3 inbox
#   drop     package the nightly EDI drop for a carrier's SFTP pickup
#   sign     sign a manifest with the exchange key
#   check    probe a carrier's HTTPS endpoint before switching a feed to it
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly SCRIPT_DIR
# shellcheck source-path=SCRIPTDIR source=../lib/crypto-utils.sh
source "$SCRIPT_DIR/../lib/crypto-utils.sh"

readonly EXPORT_CIPHER="aes-256-cbc"
readonly EXPORT_BUCKET="${EXPORT_BUCKET:-s3://tb-partner-exports-prod}"
readonly CARRIER_HOST="${CARRIER_HOST:-edi.ridgeway-freight.example}"
readonly SFTP_HOST="${SFTP_HOST:-sftp.tallowbrook.example}"

usage() {
  cat <<USAGE
usage: $(basename "$0") export <partner> <dir>
       $(basename "$0") drop <carrier> <dir>
       $(basename "$0") sign <manifest>
       $(basename "$0") check
USAGE
}

export_bundle() {
  local partner=$1 src=$2
  local work stamp
  work=$(mktemp -d)
  stamp=$(date -u +%Y%m%dT%H%M%SZ)
  require_env EXPORT_PASSPHRASE
  tar -C "$src" -cf "$work/export.tar" .
  openssl enc -"${EXPORT_CIPHER}" \
    -pbkdf2 -iter 600000 -md sha256 \
    -in "$work/export.tar" -out "$work/export.tar.enc" \
    -pass env:EXPORT_PASSPHRASE
  aws s3 cp "$work/export.tar.enc" "${EXPORT_BUCKET}/outbound/${partner}/${stamp}.tar.enc"
  rm -rf "$work"
  log_info "export for ${partner} uploaded (${stamp})"
}

drop_for_carrier() {
  local carrier=$1 src=$2
  local work
  work=$(mktemp -d)
  require_env CARRIER_EDI_PASSPHRASE CARRIER_MANIFEST_B64
  tar -C "$src" -cf "$work/edi-drop.tar" .
  base64 -d <<<"$CARRIER_MANIFEST_B64" > "$work/manifest.json"
  openssl enc -des3 \
    -salt -pass env:CARRIER_EDI_PASSPHRASE \
    -in "$work/edi-drop.tar" -out "$work/edi-drop.tar.enc"
  sftp -b - "carrier-${carrier}@${SFTP_HOST}" <<SFTP
put $work/edi-drop.tar.enc inbound/
put $work/manifest.json inbound/
SFTP
  rm -rf "$work"
  log_info "EDI drop for ${carrier} delivered"
}

sign_manifest() {
  local manifest=$1
  local sig="${manifest}.sig"
  if [[ -z "${PRIVATE_KEY_PATH:-}" ]]; then
    echo "error: PRIVATE_KEY_PATH is not set" >&2
    return 1
  fi
  openssl dgst -sign "$PRIVATE_KEY_PATH" -out "$sig" \
    -sha256 -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:32 \
    "$manifest"
  log_info "signature written to $sig"
}

check_carrier_endpoint() {
  log_info "probing ${CARRIER_HOST}:443"
  openssl s_client -connect "${CARRIER_HOST}:443" -servername "$CARRIER_HOST" \
    -tls1_2 \
    -cipher 'ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384' \
    -verify_return_error -brief </dev/null
}

main() {
  [[ $# -ge 1 ]] || { usage; exit 2; }
  require_tools openssl aws sftp tar
  case "$1" in
    export) [[ $# -eq 3 ]] || { usage; exit 2; }; export_bundle "$2" "$3" ;;
    drop) [[ $# -eq 3 ]] || { usage; exit 2; }; drop_for_carrier "$2" "$3" ;;
    sign) [[ $# -eq 2 ]] || { usage; exit 2; }; sign_manifest "$2" ;;
    check) check_carrier_endpoint ;;
    *) usage; exit 2 ;;
  esac
}

main "$@"
