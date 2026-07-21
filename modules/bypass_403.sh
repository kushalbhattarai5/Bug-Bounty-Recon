#!/usr/bin/env bash
# bypass_403.sh — checks 403/401-protected endpoints from a previous recon.sh
# run for broken access control, using header/path/port variations.
#
# This checks whether an access restriction is actually enforced
# consistently — a common and well-documented bug class (OWASP A01:2021
# Broken Access Control). It does NOT include exploit payloads (no SQLi/WAF
# bypass strings) and only uses safe, idempotent HTTP methods (GET, HEAD,
# OPTIONS) — it will never send PUT/DELETE/PATCH, which could actually
# modify or delete real data if access control turns out to be broken.
#
# Usage:
#   ./bypass_403.sh <recon_output_dir>
#
# Requires: curl
set -euo pipefail

RECON_DIR="${1:-}"
if [[ -z "$RECON_DIR" || ! -f "$RECON_DIR/live_hosts.txt" ]]; then
  echo "Usage: $0 <recon_output_dir>"
  echo "  (must be a folder previously created by recon.sh, containing live_hosts.txt)"
  exit 1
fi

OUT_MD="$RECON_DIR/bypass_403_results.md"
UA="Mozilla/5.0 (compatible; authorized-recon)"

# pull out hosts httpx flagged as 403 or 401
TARGETS=$(grep -Eo '^\S+ \[(403|401)\]' "$RECON_DIR/live_hosts.txt" | awk '{print $1}' || true)

if [[ -z "$TARGETS" ]]; then
  echo "No 403/401 hosts found in live_hosts.txt. Nothing to check."
  echo "# 403/401 bypass check" > "$OUT_MD"
  echo "" >> "$OUT_MD"
  echo "No 403/401 hosts found." >> "$OUT_MD"
  exit 0
fi

TARGET_COUNT=$(echo "$TARGETS" | grep -c . || true)
echo "Found $TARGET_COUNT host(s) returning 403/401. Testing bypass techniques..."

echo "# 403/401 bypass check" > "$OUT_MD"
echo "" >> "$OUT_MD"
echo "Every result below needs manual verification. A status change to 200" >> "$OUT_MD"
echo "does NOT confirm a real bypass — check content-length and actually" >> "$OUT_MD"
echo "view the response; soft-404 pages and generic error pages often" >> "$OUT_MD"
echo "return 200 and cause false positives." >> "$OUT_MD"
echo "" >> "$OUT_MD"

check_one() {
  local url="$1" desc="$2"
  shift 2
  local result
  result=$(curl -s -o /dev/null -w "%{http_code} %{size_download}" -m 10 -A "$UA" "$@" "$url" 2>/dev/null || echo "000 0")
  echo "$desc|$result"
}

for url in $TARGETS; do
  echo
  echo "== $url =="

  baseline=$(curl -s -o /dev/null -w "%{http_code} %{size_download}" -m 10 -A "$UA" "$url" 2>/dev/null || echo "000 0")
  base_code=$(echo "$baseline" | awk '{print $1}')

  path=$(echo "$url" | sed -E 's#^https?://[^/]+##')
  base=$(echo "$url" | sed -E 's#(https?://[^/]+).*#\1#')
  last_seg=$(basename "$path")

  echo "## $url" >> "$OUT_MD"
  echo "" >> "$OUT_MD"
  echo "Baseline: \`$baseline\`" >> "$OUT_MD"
  echo "" >> "$OUT_MD"
  echo "| Technique | Result (status size) |" >> "$OUT_MD"
  echo "|---|---|" >> "$OUT_MD"

  # --- header-based ---
  results=()
  results+=("$(check_one "$url" "Header: X-Forwarded-For: 127.0.0.1" -H "X-Forwarded-For: 127.0.0.1")")
  results+=("$(check_one "$url" "Header: X-Forwarded-For: localhost" -H "X-Forwarded-For: localhost")")
  results+=("$(check_one "$url" "Header: X-Originating-IP: 127.0.0.1" -H "X-Originating-IP: 127.0.0.1")")
  results+=("$(check_one "$url" "Header: X-Remote-IP: 127.0.0.1" -H "X-Remote-IP: 127.0.0.1")")
  results+=("$(check_one "$url" "Header: X-Client-IP: 127.0.0.1" -H "X-Client-IP: 127.0.0.1")")
  results+=("$(check_one "$url" "Header: X-Custom-IP-Authorization: 127.0.0.1" -H "X-Custom-IP-Authorization: 127.0.0.1")")
  results+=("$(check_one "$url" "Header: X-Original-URL: $path" -H "X-Original-URL: $path")")
  results+=("$(check_one "$url" "Header: X-Rewrite-URL: $path" -H "X-Rewrite-URL: $path")")

  # --- path-based ---
  results+=("$(check_one "${base}${path}/" "Path: trailing slash")")
  results+=("$(check_one "${base}${path}//" "Path: double slash")")
  results+=("$(check_one "${base}${path}/." "Path: /. suffix")")
  results+=("$(check_one "${base}${path}/..;/" "Path: /..;/ suffix")")
  results+=("$(check_one "${base}$(dirname "$path")/%2e/${last_seg}" "Path: %2e encoding")")
  results+=("$(check_one "${base}$(dirname "$path")/${last_seg}%20" "Path: trailing %20")")

  # --- safe method-based (GET/HEAD/OPTIONS only — never PUT/DELETE/PATCH) ---
  results+=("$(check_one "$url" "Method: HEAD" -X HEAD)")
  results+=("$(check_one "$url" "Method: OPTIONS" -X OPTIONS)")

  for r in "${results[@]}"; do
    desc="${r%%|*}"
    res="${r#*|}"
    code=$(echo "$res" | awk '{print $1}')
    flag=""
    if [[ "$code" == "200" && "$base_code" != "200" ]]; then
      flag=" ⚠️"
    fi
    echo "| $desc | \`$res\`$flag |" >> "$OUT_MD"
  done
  echo "" >> "$OUT_MD"
done

FLAGGED=$(grep -c '⚠️' "$OUT_MD" || true)
echo
echo "Done. $FLAGGED potential bypass(es) flagged (status changed to 200)."
echo "See: $OUT_MD"
echo "Manually verify each ⚠️ — check content-length and view the actual response."
