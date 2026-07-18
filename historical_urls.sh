#!/usr/bin/env bash
# historical_urls.sh — pulls historical URLs (Wayback Machine, Common Crawl,
# etc via gau) for a target's subdomains. Finds old endpoints that still
# work but aren't linked from anywhere live today.
#
# Usage:
#   ./historical_urls.sh <recon_output_dir>
#
# Requires: gau (installed by install_kali.sh)
set -euo pipefail

RECON_DIR="${1:-}"
if [[ -z "$RECON_DIR" || ! -f "$RECON_DIR/subdomains.txt" ]]; then
  echo "Usage: $0 <recon_output_dir>"
  echo "  (must be a folder previously created by recon.sh, containing subdomains.txt)"
  exit 1
fi

GOBIN="$(go env GOPATH 2>/dev/null)/bin"
GAU_BIN="$GOBIN/gau"
[[ ! -x "$GAU_BIN" ]] && GAU_BIN=$(command -v gau || true)
if [[ -z "$GAU_BIN" ]]; then
  echo "[!] gau not found. Run ./install_kali.sh (updated version) first."
  exit 1
fi

OUT_ALL="$RECON_DIR/historical_urls.txt"
OUT_INTERESTING="$RECON_DIR/historical_urls_interesting.txt"

echo "Pulling historical URLs (this can take a while for large targets)..."
"$GAU_BIN" --subs --threads 5 < "$RECON_DIR/subdomains.txt" > "$OUT_ALL" 2>/dev/null || true

TOTAL=$(wc -l < "$OUT_ALL" 2>/dev/null || echo 0)
echo "-> $TOTAL historical URLs found"

# Flag URLs with patterns often worth a manual look: API paths, params,
# admin/config paths, file extensions that shouldn't be public, etc.
grep -Ei '(/api/|/admin|/config|/backup|\.env|\.sql|\.log|\?.*=|/internal|/debug|/swagger|/graphql)' \
  "$OUT_ALL" 2>/dev/null | sort -u > "$OUT_INTERESTING" || true

INTERESTING_COUNT=$(wc -l < "$OUT_INTERESTING" 2>/dev/null || echo 0)
echo "-> $INTERESTING_COUNT flagged as worth a manual look"
echo
echo "All URLs:        $OUT_ALL"
echo "Flagged subset:   $OUT_INTERESTING"
echo
echo "Note: many of these will be dead/404. Check status codes before"
echo "investing time — e.g. pipe through httpx: httpx -l $OUT_INTERESTING -mc 200"
