#!/usr/bin/env bash
# Database backups for the reporting and billing replicas.
#   nightly   pg_dump -> gzip -> age -> S3 (db-backups bucket)
#   weekly    borg archive of the dump directory on the backup host
#   offline   extra copy for the offline vault, passphrase-protected with gpg
#   init      create the borg repository (once per backup host)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly SCRIPT_DIR
# shellcheck source-path=SCRIPTDIR source=../lib/crypto-utils.sh
source "$SCRIPT_DIR/../lib/crypto-utils.sh"

readonly BACKUP_RECIPIENT="age1wrxswgk8dtyjgzyjxawtcuwt962dkh6wfst4emmf35dpv9vtwahs8f32ad"
readonly BACKUP_BUCKET="${BACKUP_BUCKET:-s3://tb-db-backups-prod}"
readonly DUMP_DIR="${DUMP_DIR:-/srv/backups/dumps}"
readonly OFFLINE_DIR="${OFFLINE_DIR:-/srv/backups/offline}"
readonly PASSFILE="${PASSFILE:-/run/secrets/offline-vault-pass}"
export BORG_REPO="${BORG_REPO:-ssh://borg@backup01.internal.tallowbrook.example/srv/borg/db}"
export BORG_PASSCOMMAND="cat /run/secrets/borg-repo-pass"
export GNUPGHOME="$SCRIPT_DIR/gnupg"

usage() {
  echo "usage: $(basename "$0") nightly <database> | weekly | offline <dump.gz> | init"
}

nightly() {
  local db=$1 stamp dump
  stamp=$(date -u +%Y%m%d)
  dump="$DUMP_DIR/${db}-${stamp}.sql"
  mkdir -p "$DUMP_DIR"
  pg_dump --format=plain --no-owner --dbname="$db" --file="$dump"
  gzip -9 --stdout "$dump" > "$dump.gz"
  age --encrypt --recipient "$BACKUP_RECIPIENT" \
    --output "$dump.gz.age" "$dump.gz"
  cksum "$dump.gz.age" > "$dump.gz.age.crc"
  aws s3 cp "$dump.gz.age" "${BACKUP_BUCKET}/nightly/${db}/$(basename "$dump").gz.age"
  aws s3 cp "$dump.gz.age.crc" "${BACKUP_BUCKET}/nightly/${db}/$(basename "$dump").gz.age.crc"
  rm -f "$dump"
  log_info "nightly backup of ${db} shipped"
}

init_repo() {
  borg init --encryption=repokey-blake2 "$BORG_REPO"
  log_info "borg repository created; export the repo key to the offline vault now"
}

weekly() {
  borg create --stats --compression zstd,6 "::db-{now:%Y-%m-%d}" "$DUMP_DIR"
  borg prune --keep-weekly 8 --keep-monthly 12
}

offline_copy() {
  local dump=$1
  mkdir -p "$OFFLINE_DIR"
  gpg --batch --symmetric --passphrase-file "$PASSFILE" \
    --output "$OFFLINE_DIR/$(basename "$dump").gpg" "$dump"
  log_info "offline copy written to $OFFLINE_DIR"
}

main() {
  [[ $# -ge 1 ]] || { usage; exit 2; }
  case "$1" in
    nightly) [[ $# -eq 2 ]] || { usage; exit 2; }; require_tools pg_dump age aws; nightly "$2" ;;
    weekly) require_tools borg; weekly ;;
    offline) [[ $# -eq 2 ]] || { usage; exit 2; }; require_tools gpg; offline_copy "$2" ;;
    init) require_tools borg; init_repo ;;
    *) usage; exit 2 ;;
  esac
}

main "$@"
