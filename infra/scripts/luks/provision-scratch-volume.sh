#!/usr/bin/env bash
# Formats and mounts the local NVMe scratch volume on analytics workers. The
# key file lives in tmpfs, so the volume is unreadable after a reboot; the
# node re-provisions it on boot.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly SCRIPT_DIR
# shellcheck source-path=SCRIPTDIR source=../lib/crypto-utils.sh
source "$SCRIPT_DIR/../lib/crypto-utils.sh"

readonly DEVICE="${DEVICE:-/dev/nvme1n1}"
readonly MAPPER_NAME="scratch"
readonly MOUNT_POINT="/mnt/scratch"
readonly KEY_FILE="/run/scratch/volume.key"

usage() {
  echo "usage: $(basename "$0")   (DEVICE=${DEVICE})"
}

main() {
  [[ "${1:-}" == "-h" ]] && { usage; exit 0; }
  [[ $EUID -eq 0 ]] || die "run as root"
  [[ -b "$DEVICE" ]] || die "no block device at $DEVICE"
  require_tools cryptsetup mkfs.xfs

  mkdir -p "$(dirname "$KEY_FILE")"
  mount -t tmpfs -o size=1m,mode=0700 tmpfs "$(dirname "$KEY_FILE")"
  head -c 64 /dev/urandom > "$KEY_FILE"

  cryptsetup luksFormat --batch-mode \
    --type luks2 \
    --cipher aes-xts-plain64 --key-size 512 \
    --pbkdf argon2id --pbkdf-memory 1048576 --pbkdf-parallel 4 \
    --key-file "$KEY_FILE" \
    "$DEVICE"
  cryptsetup open --key-file "$KEY_FILE" "$DEVICE" "$MAPPER_NAME"

  mkfs.xfs -q -f "/dev/mapper/$MAPPER_NAME"
  mkdir -p "$MOUNT_POINT"
  mount -o noatime "/dev/mapper/$MAPPER_NAME" "$MOUNT_POINT"
  chown 1000:1000 "$MOUNT_POINT"
  log_info "scratch volume mounted at $MOUNT_POINT"
}

main "$@"
