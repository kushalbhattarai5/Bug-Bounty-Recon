#!/usr/bin/env bash
# js_analysis.sh — crawls JS files from a previous recon.sh run and scans
# them for leaked secrets/tokens and interesting endpoints.
#
# Run this AFTER recon.sh has already produced a results folder.
#
# Usage:
#   ./js_analysis.sh <recon_output_dir>
#
# Example:
#   ./js_analysis.sh results/gojekapi.com_20260713_124039
#
# Requires: katana (JS/endpoint crawler). Install with install_kali.sh.
#
set -euo pipefail

RECON_DIR="${1:-}"
if [[ -z "$RECON_DIR" || ! -f "$RECON_DIR/live_hosts_clean.txt" ]]; then
  echo "Usage: $0 <recon_output_dir>"
  echo "  (must be a folder previously created by recon.sh, containing live_hosts_clean.txt)"
  exit 1
fi

GOBIN="$(go env GOPATH 2>/dev/null)/bin"
KATANA_BIN="$GOBIN/katana"
[[ ! -x "$KATANA_BIN" ]] && KATANA_BIN=$(command -v katana || true)
if [[ -z "$KATANA_BIN" ]]; then
  echo "[!] katana not found. Run ./install_kali.sh (updated version) first."
  exit 1
fi

JSDIR="$RECON_DIR/js"
mkdir -p "$JSDIR/files"

echo "[1/3] Crawling for JS files and endpoints referenced inside them..."
"$KATANA_BIN" -list "$RECON_DIR/live_hosts_clean.txt" -silent \
  -jc -jsl \
  -o "$JSDIR/crawl_all.txt" || true

# split crawl output: JS file URLs vs everything else (endpoints found)
grep -Ei '\.js(\?|$)' "$JSDIR/crawl_all.txt" 2>/dev/null | sort -u > "$JSDIR/js_urls.txt" || true
grep -Eiv '\.js(\?|$)' "$JSDIR/crawl_all.txt" 2>/dev/null | sort -u > "$JSDIR/endpoints.txt" || true

JS_COUNT=$(wc -l < "$JSDIR/js_urls.txt" 2>/dev/null || echo 0)
EP_COUNT=$(wc -l < "$JSDIR/endpoints.txt" 2>/dev/null || echo 0)
echo "      -> $JS_COUNT JS files found, $EP_COUNT other endpoints"

echo "[2/3] Downloading JS files..."
i=0
while IFS= read -r url; do
  [[ -z "$url" ]] && continue
  i=$((i+1))
  fname=$(echo "$url" | sed -E 's#[^a-zA-Z0-9._-]#_#g' | cut -c1-150)
  curl -s -m 15 -A "Mozilla/5.0 (compatible; authorized-recon)" "$url" \
    -o "$JSDIR/files/${i}_${fname}" 2>/dev/null || true
done < "$JSDIR/js_urls.txt"
echo "      -> downloaded to $JSDIR/files/"

echo "[3/3] Scanning downloaded JS for secrets and endpoints..."
python3 "$(dirname "$0")/js_secret_scan.py" "$JSDIR/files" "$JSDIR/js_findings.md" "$RECON_DIR/live_hosts_clean.txt" > /dev/null

echo
echo "Done. See:"
echo "  $JSDIR/js_urls.txt      — all discovered JS file URLs"
echo "  $JSDIR/endpoints.txt    — other endpoints katana found while crawling"
echo "  $JSDIR/js_findings.md   — possible secrets/endpoints found inside JS"
echo
echo "As always: treat every match as a lead, not a confirmed finding — verify by hand."
