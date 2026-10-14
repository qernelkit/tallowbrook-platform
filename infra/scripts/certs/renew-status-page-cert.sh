#!/usr/bin/env bash
# Issues or renews the status.tallowbrook.example certificate on the status
# host and reloads nginx when it changes. Runs from a systemd timer.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly SCRIPT_DIR
# shellcheck source-path=SCRIPTDIR source=../lib/crypto-utils.sh
source "$SCRIPT_DIR/../lib/crypto-utils.sh"

readonly CONF="$SCRIPT_DIR/cli.ini"
readonly DOMAIN="status.tallowbrook.example"

usage() {
  echo "usage: $(basename "$0") [--dry-run]"
}

main() {
  local extra=()
  case "${1:-}" in
    --dry-run) extra=(--dry-run) ;;
    -h | --help) usage; exit 0 ;;
    "") ;;
    *) usage; exit 2 ;;
  esac
  require_tools certbot
  certbot certonly --config "$CONF" -d "$DOMAIN" --cert-name status-page \
    --keep-until-expiring --deploy-hook "systemctl reload nginx" "${extra[@]}"
  log_info "status page certificate checked"
}

main "$@"
