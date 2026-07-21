#!/usr/bin/env bash
# takeover_check.sh — checks a previous recon.sh run's subdomains for
# possible subdomain takeover (dangling CNAME pointing to an unclaimed
# cloud resource: S3, GitHub Pages, Heroku, Azure, etc).
#
# Run this AFTER recon.sh has already produced a results folder.
#
# Usage:
#   ./takeover_check.sh <recon_output_dir>
#
# Example:
#   ./takeover_check.sh results/gojekapi.com_20260713_124039
#
# Note: this checks the FULL subdomain list, not just "live" hosts from
# httpx — dangling CNAMEs often still respond to HTTP (with the cloud
# provider's own "not found" page) even though httpx may not flag them
# as a normal live host.
set -euo pipefail

RECON_DIR="${1:-}"
if [[ -z "$RECON_DIR" || ! -f "$RECON_DIR/subdomains.txt" ]]; then
  echo "Usage: $0 <recon_output_dir>"
  echo "  (must be a folder previously created by recon.sh, containing subdomains.txt)"
  exit 1
fi

GOBIN="$(go env GOPATH 2>/dev/null)/bin"
NUCLEI_BIN="$GOBIN/nuclei"
[[ ! -x "$NUCLEI_BIN" ]] && NUCLEI_BIN=$(command -v nuclei || true)
if [[ -z "$NUCLEI_BIN" ]]; then
  echo "[!] nuclei not found. Run ./install_kali.sh first."
  exit 1
fi

OUT_TXT="$RECON_DIR/takeover_results.txt"
OUT_JSON="$RECON_DIR/takeover_results.json"

SUB_COUNT=$(wc -l < "$RECON_DIR/subdomains.txt")
echo "Checking $SUB_COUNT subdomains for possible takeover..."

"$NUCLEI_BIN" -l "$RECON_DIR/subdomains.txt" \
  -tags takeover \
  -silent \
  -o "$OUT_TXT" \
  -je "$OUT_JSON" || true

COUNT=0
if [[ -f "$OUT_JSON" ]]; then
  COUNT=$(python3 -c "import json,sys
try:
    print(len(json.load(open(sys.argv[1]))))
except Exception:
    print(0)" "$OUT_JSON")
fi

echo
if [[ "$COUNT" -eq 0 ]]; then
  echo "No possible takeovers found."
else
  echo "!! $COUNT possible subdomain takeover(s) found !!"
  echo "See: $OUT_TXT (readable) or $OUT_JSON (structured)"
  echo
  echo "Next steps — do NOT skip these:"
  echo "  1. Manually visit each flagged host and confirm the error page"
  echo "     genuinely matches an unclaimed-resource signature (not a"
  echo "     coincidental match)."
  echo "  2. Check the CNAME with: dig CNAME <subdomain>"
  echo "  3. Only attempt to claim/verify the resource if the program's"
  echo "     rules of engagement explicitly allow it — claiming a real"
  echo "     cloud resource, even to prove impact, has real-world effects"
  echo "     and should follow the program's disclosure process, not be"
  echo "     done unilaterally."
fi
