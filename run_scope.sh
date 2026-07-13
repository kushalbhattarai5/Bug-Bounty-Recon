#!/usr/bin/env bash
# run_scope.sh — run recon.sh across every domain in a scope file.
#
# Confirms authorization ONCE up front (not per-domain), then loops.
# Good for automation/cron since recon.sh's per-target confirmation
# would otherwise block unattended runs.
#
# Usage:
#   ./run_scope.sh scope.txt [output_base_dir]
#
# scope.txt format: one root domain per line, '#' for comments, blank lines ignored.
#   example.com
#   api.example.org
#   # this one is out of scope, skip:
#   # excluded.example.com

set -euo pipefail

SCOPE_FILE="${1:-}"
OUTBASE="${2:-results}"

if [[ -z "$SCOPE_FILE" || ! -f "$SCOPE_FILE" ]]; then
  echo "Usage: $0 <scope_file.txt> [output_base_dir]"
  exit 1
fi

TARGETS=$(grep -vE '^\s*(#|$)' "$SCOPE_FILE")
COUNT=$(echo "$TARGETS" | grep -c . || true)

echo "Scope file: $SCOPE_FILE"
echo "Targets ($COUNT):"
echo "$TARGETS" | sed 's/^/  - /'
echo
echo "!! By continuing you confirm ALL of the above are in your authorized"
echo "!! bug bounty scope, checked against the program's current scope page. !!"
read -r -p "Type YES to proceed: " CONFIRM
if [[ "$CONFIRM" != "YES" ]]; then
  echo "Not confirmed. Aborting."
  exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TS=$(date +%Y%m%d_%H%M%S)
RUN_DIR="$OUTBASE/scope_run_${TS}"
mkdir -p "$RUN_DIR"

SUMMARY="$RUN_DIR/summary.md"
echo "# Scope Run Summary — $TS" > "$SUMMARY"
echo "" >> "$SUMMARY"

while IFS= read -r target; do
  [[ -z "$target" ]] && continue
  echo
  echo "=============================================="
  echo " Running recon on: $target"
  echo "=============================================="
  TARGET_OUT="$RUN_DIR/$target"
  mkdir -p "$TARGET_OUT"

  # auto-confirm the per-target prompt inside recon.sh since we already
  # confirmed the whole scope above
  echo "$target" | "$SCRIPT_DIR/recon.sh" -d "$target" -o "$TARGET_OUT" \
    || echo "  [!] recon.sh failed for $target — continuing with next target"

  FINDINGS=0
  if [[ -f "$TARGET_OUT/nuclei_results.json" ]]; then
    FINDINGS=$(python3 -c "import json,sys
try:
    print(len(json.load(open(sys.argv[1]))))
except Exception:
    print(0)" "$TARGET_OUT/nuclei_results.json")
  fi
  echo "- **$target**: $FINDINGS nuclei findings — see [$target/report.md]($target/report.md)" >> "$SUMMARY"
done <<< "$TARGETS"

echo
echo "All targets processed."
echo "Summary: $SUMMARY"
