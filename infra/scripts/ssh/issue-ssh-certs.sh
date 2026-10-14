#!/usr/bin/env bash
# SSH credentials for the platform:
#   deploy-key <repo>   new CI deploy key; public half to the repo, private half to the CI secret
#   host-certs          sign the bastion host keys collected in $INBOX_DIR and roll them out
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly SCRIPT_DIR
# shellcheck source-path=SCRIPTDIR source=../lib/crypto-utils.sh
source "$SCRIPT_DIR/../lib/crypto-utils.sh"

readonly HOST_CA_KEY="${HOST_CA_KEY:-/etc/tallowbrook/ssh/host_ca}"
readonly INBOX_DIR="${INBOX_DIR:-/srv/ssh-ca/inbox}"
readonly GH_ORG="tallowbrook"

usage() {
  echo "usage: $(basename "$0") deploy-key <repo> | host-certs"
}

new_deploy_key() {
  local repo=$1 workdir
  workdir=$(mktemp -d)
  trap 'rm -rf "$workdir"' RETURN
  ssh-keygen -q -t ed25519 -N "" -C "deploy@ci" -f "$workdir/id_deploy"
  gh repo deploy-key add "$workdir/id_deploy.pub" --repo "${GH_ORG}/${repo}" --title "ci-$(date -u +%Y%m)"
  gh secret set DEPLOY_SSH_KEY --repo "${GH_ORG}/${repo}" < "$workdir/id_deploy"
  log_info "deploy key for ${repo} installed"
}

sign_host_key() {
  local pubkey=$1 host
  host=$(basename "$pubkey" .pub)
  ssh-keygen -s "$HOST_CA_KEY" -t rsa-sha2-512 -h \
    -I "$host" -n "$host,${host}.internal.tallowbrook.example" -V +52w "$pubkey"
  salt -C 'G@role:bastion' state.apply sshd.host_cert
}

main() {
  [[ $# -ge 1 ]] || { usage; exit 2; }
  case "$1" in
    deploy-key)
      [[ $# -eq 2 ]] || { usage; exit 2; }
      require_tools gh
      new_deploy_key "$2"
      ;;
    host-certs)
      [[ -r "$HOST_CA_KEY" ]] || die "host CA key not readable: $HOST_CA_KEY"
      require_tools salt
      local pub
      for pub in "$INBOX_DIR"/*.pub; do
        [[ -e "$pub" ]] || continue
        sign_host_key "$pub"
      done
      ;;
    *) usage; exit 2 ;;
  esac
}

main "$@"
