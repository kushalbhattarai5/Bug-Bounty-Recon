#!/usr/bin/env bash
# screenshot.sh — takes a screenshot of every live host from a previous
# recon.sh run, so you can visually skim 100+ hosts instead of reading text.
#
# Usage:
#   ./screenshot.sh <recon_output_dir>
#
# Requires: gowitness (installed by install_kali.sh)
set -euo pipefail

RECON_DIR="${1:-}"
if [[ -z "$RECON_DIR" || ! -f "$RECON_DIR/live_hosts_clean.txt" ]]; then
  echo "Usage: $0 <recon_output_dir>"
  echo "  (must be a folder previously created by recon.sh, containing live_hosts_clean.txt)"
  exit 1
fi

GOBIN="$(go env GOPATH 2>/dev/null)/bin"
GOWITNESS_BIN="$GOBIN/gowitness"
[[ ! -x "$GOWITNESS_BIN" ]] && GOWITNESS_BIN=$(command -v gowitness || true)
if [[ -z "$GOWITNESS_BIN" ]]; then
  echo "[!] gowitness not found. Run ./install_kali.sh (updated version) first."
  exit 1
fi

SHOTS_DIR="$RECON_DIR/screenshots"
mkdir -p "$SHOTS_DIR"

HOST_COUNT=$(wc -l < "$RECON_DIR/live_hosts_clean.txt")
echo "Screenshotting $HOST_COUNT hosts..."

"$GOWITNESS_BIN" scan file -f "$RECON_DIR/live_hosts_clean.txt" \
  --screenshot-path "$SHOTS_DIR" \
  --write-jsonl \
  --write-jsonl-file "$SHOTS_DIR/gowitness_results.jsonl" \
  --threads 4 || true

SHOT_COUNT=$(find "$SHOTS_DIR" -name "*.png" 2>/dev/null | wc -l)
echo
echo "Done. $SHOT_COUNT screenshots saved to: $SHOTS_DIR"
echo "Open the folder and skim visually — much faster than reading URLs one by one."
echo "Look for: login pages, admin panels, default install pages, error pages"
echo "that reveal software versions, or anything that looks out of place."