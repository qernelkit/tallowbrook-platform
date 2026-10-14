#!/usr/bin/env bash
# Split a PEM bundle into one file per object so each can be inspected on its own.
set -euo pipefail

bundle="${1:?usage: split-bundle.sh BUNDLE [OUTDIR]}"
outdir="${2:-split}"
mkdir -p "$outdir"
csplit -s -z -f "${outdir}/cert-" "$bundle" '/-----BEGIN CERTIFICATE-----/' '{*}'
count=$(find "$outdir" -name 'cert-*' | wc -l | tr -d ' ')
echo "split ${bundle} into ${count} certificate files under ${outdir}"
