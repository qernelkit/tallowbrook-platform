#!/usr/bin/env bash
# Keys and requests for internal services, the edge listener, the archive
# escrow, the internal CA certificate and partner client certificates.
# Certificates for services come back from Vault PKI; this script only makes
# keys, requests and bundles.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly SCRIPT_DIR
readonly CONF_DIR="$SCRIPT_DIR"
readonly OUT_DIR="${OUT_DIR:-$PWD/issued}"
readonly CA_KEY="${CA_KEY:-/srv/offline-ca/internal-ca.key}"
# shellcheck source-path=SCRIPTDIR source=../lib/crypto-utils.sh
source "$SCRIPT_DIR/../lib/crypto-utils.sh"

usage() {
  cat <<USAGE
usage: $(basename "$0") <command> [args]

  service-key <svc>        new signing key for an internal service
  edge-key <env>           new key for the public edge listener (sent to PKI)
  escrow-key <year>        new archive escrow key pair
  renew-ca                 reissue the internal CA certificate from the offline key
  partner-csr <partner>    key and request for a partner client certificate
  bundle <svc>             PKCS#12 bundle of a service key, certificate and chain

Output goes to \$OUT_DIR (default: ./issued).
USAGE
}

cmd_service_key() {
  local svc=$1 out=$OUT_DIR
  [[ -e "$out/${svc}.key" ]] && die "$out/${svc}.key exists; remove it first"
  openssl genpkey -algorithm ED25519 -out "$out/${svc}.key"
  chmod 0400 "$out/${svc}.key"
  log_info "new key for ${svc}; request its certificate from Vault (role internal-services)"
}

cmd_edge_key() {
  local env=$1 out=$OUT_DIR
  local crt="$out/edge-${env}.crt"
  openssl genpkey -algorithm ML-DSA-65 -out "$out/edge-${env}.key"
  grep -q -- '-----BEGIN CERTIFICATE-----' "$crt" || die "not a PEM certificate: $crt"
  openssl pkey -in "$out/edge-${env}.key" -pubout -out "$out/edge-${env}.pub"
  tar -C "$out" -czf "$out/edge-${env}-request.tgz" "edge-${env}.pub" "edge-${env}.crt"
  log_info "send edge-${env}-request.tgz to PKI; they revoke the current certificate on issue"
}

cmd_escrow_key() {
  local year=$1 out=$OUT_DIR
  openssl genpkey -algorithm ML-KEM-1024 -out "$out/escrow-${year}.key"
  openssl pkey -in "$out/escrow-${year}.key" -pubout -out "$out/escrow-${year}.pub.pem"
  chmod 0400 "$out/escrow-${year}.key"
  log_info "escrow-${year}.pub.pem goes to the archive service; the key goes to the vault safe"
}

cmd_renew_ca() {
  local out=$OUT_DIR
  [[ -r "$CA_KEY" ]] || die "CA key not readable: $CA_KEY (run this on the offline host)"
  openssl req -x509 -config "$CONF_DIR/internal-ca.cnf" -key "$CA_KEY" \
    -days 1826 -set_serial "0x$(date -u +%Y%m%d)01" -out "$out/internal-ca.crt"
  log_info "new CA certificate at $out/internal-ca.crt"
}

cmd_partner_csr() {
  local partner=$1 out=$OUT_DIR
  openssl req -new -config "$CONF_DIR/partner-csr.cnf" -noenc \
    -subj "/C=US/O=Tallowbrook Logistics/OU=Partner Integrations/CN=${partner}.partners.tallowbrook.example" \
    -keyout "$out/partner-${partner}.key" -out "$out/partner-${partner}.req"
  log_info "send partner-${partner}.req to ${partner}'s portal; keep the key in the partner vault"
}

cmd_bundle() {
  local svc=$1 out=$OUT_DIR
  local bundle="$out/${svc}-chain.pem"
  [[ -f "$out/${svc}.crt" && -f "$bundle" ]] || die "missing ${svc}.crt or ${svc}-chain.pem in $out"
  require_env P12_PASS
  csplit -s -z -f "$out/chain-" "$bundle" '/-----BEGIN CERTIFICATE-----/' '{*}'
  openssl pkcs12 -export \
    -keypbe AES-256-CBC -certpbe AES-256-CBC \
    -in "$out/${svc}.crt" \
    -inkey "$out/${svc}.key" \
    -certfile "$out/chain-01" \
    -name "$svc" \
    -passout env:P12_PASS \
    -out "$out/${svc}.p12"
  rm -f "$out"/chain-0*
  log_info "bundle at $out/${svc}.p12"
}

main() {
  [[ $# -ge 1 ]] || { usage; exit 2; }
  require_tools openssl csplit tar
  mkdir -p "$OUT_DIR"
  local cmd=$1
  shift
  case "$cmd" in
    service-key) [[ $# -eq 1 ]] || die "service-key needs a service name"; cmd_service_key "$1" ;;
    edge-key) [[ $# -eq 1 ]] || die "edge-key needs an environment"; cmd_edge_key "$1" ;;
    escrow-key) [[ $# -eq 1 ]] || die "escrow-key needs a year"; cmd_escrow_key "$1" ;;
    renew-ca) cmd_renew_ca ;;
    partner-csr) [[ $# -eq 1 ]] || die "partner-csr needs a partner name"; cmd_partner_csr "$1" ;;
    bundle) [[ $# -eq 1 ]] || die "bundle needs a service name"; cmd_bundle "$1" ;;
    -h | --help) usage ;;
    *) usage; exit 2 ;;
  esac
}

main "$@"
