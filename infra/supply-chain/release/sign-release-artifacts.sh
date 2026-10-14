#!/usr/bin/env bash
# Signs the two release artifacts that are not container images:
#   jar <settlement.jar>   the settlement batch JAR shipped to the bank's SFTP
#   apk <driver.apk>       the driver app build uploaded to the Play Console
# Keystore passwords come from the release job's environment.
set -euo pipefail

readonly VERSION="${VERSION:?set VERSION to the release tag}"
readonly OUT_DIR="${OUT_DIR:-$PWD/signed}"
readonly TSA_URL="${TSA_URL:-https://timestamp.digicert.com}"
readonly JAR_KEYSTORE="${JAR_KEYSTORE:?set JAR_KEYSTORE to the settlement signing store}"
readonly UPLOAD_KEYSTORE="${UPLOAD_KEYSTORE:-/etc/tallowbrook/pki/keystores/android-upload.jks}"

usage() {
  echo "usage: $(basename "$0") jar <settlement.jar> | apk <driver.apk>"
}

sign_settlement_jar() {
  local jar=$1
  jarsigner -keystore "$JAR_KEYSTORE" -storetype PKCS12 \
    -storepass:env JAR_STOREPASS \
    -sigalg SHA256withRSA \
    -digestalg SHA-256 \
    -tsa "$TSA_URL" -tsadigestalg SHA-512 \
    -signedjar "$OUT_DIR/settlement-${VERSION}.jar" \
    "$jar" settlement-release
  jarsigner -verify -strict "$OUT_DIR/settlement-${VERSION}.jar"
}

sign_driver_apk() {
  local apk=$1
  apksigner sign --ks "$UPLOAD_KEYSTORE" --ks-key-alias upload \
    --ks-pass env:UPLOAD_KS_PASS \
    --min-sdk-version 21 \
    --v1-signing-enabled true \
    --out "$OUT_DIR/driver-${VERSION}.apk" "$apk"
  apksigner verify --min-sdk-version 21 "$OUT_DIR/driver-${VERSION}.apk"
}

main() {
  [[ $# -eq 2 ]] || { usage; exit 2; }
  mkdir -p "$OUT_DIR"
  case "$1" in
    jar) sign_settlement_jar "$2" ;;
    apk) sign_driver_apk "$2" ;;
    *) usage; exit 2 ;;
  esac
}

main "$@"
