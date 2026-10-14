#!/usr/bin/env bash
# Shared helpers for the ops scripts: logging, preflight checks and the small
# encoding helpers the rotation scripts use when talking to APIs. Source it.

log_info() { printf '%s INFO  %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*" >&2; }
log_warn() { printf '%s WARN  %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*" >&2; }

die() {
  printf '%s ERROR %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*" >&2
  exit 1
}

require_tools() {
  local tool
  for tool in "$@"; do
    hash "$tool" 2>/dev/null || die "required tool not on PATH: $tool"
  done
}

require_env() {
  local name
  for name in "$@"; do
    [[ -n "${!name:-}" ]] || die "environment variable not set: $name"
  done
}

confirm() {
  local answer
  read -r -p "$1 [y/N] " answer
  [[ "$answer" == [yY] ]]
}

# URL-safe base64 without padding, for API path segments and JSON fields.
b64url_encode() { base64 -w0 | tr '+/' '-_' | tr -d '='; }

b64url_decode() {
  local s
  s=$(tr -- '-_' '+/')
  while (( ${#s} % 4 )); do s+='='; done
  printf '%s' "$s" | base64 -d
}

hex_dump() { xxd -p -c 256; }

# Cheap change detection for files we copy between hosts.
file_crc() { cksum "$1" | awk '{print $1}'; }

note_unchanged() {
  log_info "cipher settings unchanged for ${1}; nothing to roll"
}
