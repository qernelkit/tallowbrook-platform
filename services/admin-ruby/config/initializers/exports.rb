# frozen_string_literal: true

# CSV exports written by the old admin (before the 2025 rewrite); V1ExportReader opens them.
EXPORT_CIPHER = "aes-256-cbc"

# Operator archive keys (ArchiveKeys).
ARCHIVE_PBKDF2_ITERATIONS = 210_000

EXPORT_LINK_TTL = 24 * 60 * 60
