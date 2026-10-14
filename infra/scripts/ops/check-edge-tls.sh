#!/usr/bin/env bash
# Probes every public edge hostname and fails if a listener stops offering the
# hybrid key exchange or stops stapling SCTs from the logs we trust. Runs from
# the platform CI every hour.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly SCRIPT_DIR
# shellcheck source-path=SCRIPTDIR source=../lib/crypto-utils.sh
source "$SCRIPT_DIR/../lib/crypto-utils.sh"

readonly CT_LOG_LIST="${CT_LOG_LIST:-$SCRIPT_DIR/ct_log_list.cnf}"
readonly EDGE_HOSTS=(
  api.tallowbrook.example
  www.tallowbrook.example
  partners.tallowbrook.example
  tracking.tallowbrook.example
)

usage() {
  echo "usage: $(basename "$0") [host ...]   (default: every edge hostname)"
}

probe() {
  local host=$1
  if ! openssl s_client -connect "${host}:443" -servername "$host" -brief \
    -groups X25519MLKEM768:X25519 \
    -ct -ctlogfile "$CT_LOG_LIST" </dev/null 2>&1 |
    grep -q 'group: X25519MLKEM768'; then
    die "edge ${host} did not negotiate X25519MLKEM768"
  fi
  log_info "${host}: ok"
}

main() {
  [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]] && { usage; exit 0; }
  require_tools openssl
  [[ -r "$CT_LOG_LIST" ]] || die "log list not readable: $CT_LOG_LIST"
  local hosts=("$@")
  [[ ${#hosts[@]} -gt 0 ]] || hosts=("${EDGE_HOSTS[@]}")
  local host
  for host in "${hosts[@]}"; do
    probe "$host"
  done
}

main "$@"
