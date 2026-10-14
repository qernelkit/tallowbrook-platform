#!/usr/bin/env bash
# Rotates the reports SPNEGO keytab (HTTP/reports.tallowbrook.example) before
# the nightly AD sync, then reseals it for the prod overlay.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly SCRIPT_DIR
# shellcheck source-path=SCRIPTDIR source=../lib/crypto-utils.sh
source "$SCRIPT_DIR/../lib/crypto-utils.sh"

readonly REALM="TALLOWBROOK.EXAMPLE"
readonly HOST="reports.tallowbrook.example"
readonly ADMIN_PRINC="${ADMIN_PRINC:-svc-keytab-rotate@TALLOWBROOK.EXAMPLE}"
readonly ADMIN_KEYTAB="${ADMIN_KEYTAB:-/etc/tallowbrook/kerberos/keytab-rotate.keytab}"
# The reporting cluster's AD still has two domain controllers that only take RC4
# for this principal; drop rc4-hmac once they are replaced.
readonly ENCTYPES="aes256-cts-hmac-sha1-96:normal,aes128-cts-hmac-sha1-96:normal,rc4-hmac:normal"

usage() {
  echo "usage: $(basename "$0") <output.sealed.yaml>"
}

main() {
  [[ $# -eq 1 ]] || { usage; exit 2; }
  local out=$1 work
  require_tools kadmin kubectl kubeseal
  work=$(mktemp -d)
  trap 'rm -rf "$work"' EXIT
  readonly KEYTAB="$work/http.keytab"

  kadmin -p "$ADMIN_PRINC" -k -t "$ADMIN_KEYTAB" -q "ktadd -k ${KEYTAB} -e ${ENCTYPES} HTTP/${HOST}@${REALM}"

  kubectl create secret generic reports-http-keytab --namespace reports \
    --from-file=krb5.keytab="$KEYTAB" --dry-run=client -o yaml \
    | kubeseal --controller-namespace kube-system --format yaml > "$out"
  log_info "sealed keytab written to $out; commit it to the prod overlay"
}

main "$@"
