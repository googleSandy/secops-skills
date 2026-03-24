#!/usr/bin/env bash
# lookup_log_type.sh — look up metadata.log_type values from the SecOps reference files
#
# Usage:
#   ./lookup_log_type.sh "Prisma Cloud"
#   ./lookup_log_type.sh "CrowdStrike"
#
# Returns: matching rows from all-log-types.md.
# If nothing is found, says so — do NOT guess a value.

set -euo pipefail

if [ $# -eq 0 ]; then
  echo "Usage: lookup_log_type.sh <vendor or product name>"
  echo "Example: lookup_log_type.sh \"Prisma Cloud\""
  exit 1
fi

SEARCH="$*"

# Sanitize: allow only letters, numbers, spaces, hyphens, underscores.
# Rejects shell metacharacters, path traversal, and injection attempts.
if ! echo "$SEARCH" | grep -qE '^[a-zA-Z0-9 _-]+$'; then
  echo "ERROR: Invalid input. Only letters, numbers, spaces, hyphens, and underscores are allowed."
  exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REFS="$SCRIPT_DIR/../references"

FILES=(
  "$REFS/all-log-types.md"
)

FOUND=0

for FILE in "${FILES[@]}"; do
  [ -f "$FILE" ] || continue
  MATCHES=$(grep -i "$SEARCH" "$FILE" | grep "^| \`" || true)
  if [ -n "$MATCHES" ]; then
    echo "=== $(basename "$FILE" .md) ==="
    echo "$MATCHES"
    echo ""
    FOUND=1
  fi
done

if [ "$FOUND" -eq 0 ]; then
  echo "NOT FOUND: \"$SEARCH\" is not in the reference files."
  echo "Do not guess. Run the discovery query to see what is actually ingested:"
  echo ""
  echo '  $log_type = metadata.log_type'
  echo '  $log_type != ""'
  echo '  match:'
  echo '    $log_type'
  echo '  outcome:'
  echo '    $count = count(metadata.id)'
  echo '  order:'
  echo '    $count desc'
fi
