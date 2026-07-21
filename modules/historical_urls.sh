#!/usr/bin/env bash
# historical_urls.sh — pulls historical URLs (Wayback Machine, Common Crawl,
# etc via gau), then automatically triages them:
#   1. Pull historical URLs for all subdomains
#   2. Filter out dead links (check which still respond)
#   3. Categorize survivors by risk type (sensitive files, admin panels,
#      API docs, URLs with parameters)
#   4. Re-scan survivors with nuclei (old endpoints can run older,
#      more vulnerable software than what's currently deployed)
#   5. Write a summary report
#
# Usage:
#   ./historical_urls.sh <recon_output_dir>
#
# Requires: gau, httpx, nuclei (all installed by install_kali.sh)
set -euo pipefail

RECON_DIR="${1:-}"
if [[ -z "$RECON_DIR" || ! -f "$RECON_DIR/subdomains.txt" ]]; then
  echo "Usage: $0 <recon_output_dir>"
  echo "  (must be a folder previously created by recon.sh, containing subdomains.txt)"
  exit 1
fi

GOBIN="$(go env GOPATH 2>/dev/null)/bin"
resolve_tool() {
  local name="$1"
  if [[ -x "$GOBIN/$name" ]]; then
    echo "$GOBIN/$name"
  else
    command -v "$name" 2>/dev/null || true
  fi
}
GAU_BIN=$(resolve_tool gau)
HTTPX_BIN=$(resolve_tool httpx)
NUCLEI_BIN=$(resolve_tool nuclei)

if [[ -z "$GAU_BIN" ]]; then
  echo "[!] gau not found. Run ./install_kali.sh (updated version) first."
  exit 1
fi

HDIR="$RECON_DIR/historical"
mkdir -p "$HDIR"

OUT_ALL="$HDIR/all_urls.txt"
OUT_ALIVE="$HDIR/alive_urls.txt"
OUT_SENSITIVE="$HDIR/sensitive_files.txt"
OUT_ADMIN="$HDIR/admin_panels.txt"
OUT_API="$HDIR/api_docs.txt"
OUT_PARAMS="$HDIR/urls_with_params.txt"
OUT_REPORT="$HDIR/report.md"

# ---------- 1. Pull historical URLs ----------
echo "[1/4] Pulling historical URLs (can take a while for large targets)..."
"$GAU_BIN" --subs --threads 5 < "$RECON_DIR/subdomains.txt" > "$OUT_ALL" 2>/dev/null || true
sort -u -o "$OUT_ALL" "$OUT_ALL"
TOTAL=$(wc -l < "$OUT_ALL" 2>/dev/null || echo 0)
echo "      -> $TOTAL historical URLs found"

# ---------- 2. Filter out dead links ----------
if [[ -z "$HTTPX_BIN" || "$TOTAL" -eq 0 ]]; then
  echo "[2/4] Skipping alive-check (httpx not found or no URLs to check)"
  cp "$OUT_ALL" "$OUT_ALIVE" 2>/dev/null || touch "$OUT_ALIVE"
else
  echo "[2/4] Checking which URLs still respond (this is the slow part)..."
  "$HTTPX_BIN" -l "$OUT_ALL" -silent -mc 200,201,301,302,401,403 \
    -threads 50 -timeout 8 -o "$OUT_ALIVE" || true
fi
ALIVE_COUNT=$(wc -l < "$OUT_ALIVE" 2>/dev/null || echo 0)
echo "      -> $ALIVE_COUNT still respond ($((TOTAL - ALIVE_COUNT)) dead/filtered out)"

# extract bare URL (httpx output may include status code brackets)
awk '{print $1}' "$OUT_ALIVE" > "$HDIR/alive_urls_clean.txt" 2>/dev/null || cp "$OUT_ALIVE" "$HDIR/alive_urls_clean.txt"

# ---------- 3. Categorize by risk type ----------
echo "[3/4] Categorizing by risk type..."
grep -Ei '\.(env|sql|log|bak|backup|old|zip|tar|gz|config|conf|yml|yaml)($|\?)' \
  "$HDIR/alive_urls_clean.txt" 2>/dev/null | sort -u > "$OUT_SENSITIVE" || true
grep -Ei '(/admin|/internal|/debug|/manage|/console|/dashboard)' \
  "$HDIR/alive_urls_clean.txt" 2>/dev/null | sort -u > "$OUT_ADMIN" || true
grep -Ei '(/swagger|/graphql|/api-docs|/openapi|\.wsdl)' \
  "$HDIR/alive_urls_clean.txt" 2>/dev/null | sort -u > "$OUT_API" || true
grep -E '\?[a-zA-Z0-9_]+=' \
  "$HDIR/alive_urls_clean.txt" 2>/dev/null | sort -u > "$OUT_PARAMS" || true

SENS_COUNT=$(wc -l < "$OUT_SENSITIVE" 2>/dev/null || echo 0)
ADMIN_COUNT=$(wc -l < "$OUT_ADMIN" 2>/dev/null || echo 0)
API_COUNT=$(wc -l < "$OUT_API" 2>/dev/null || echo 0)
PARAM_COUNT=$(wc -l < "$OUT_PARAMS" 2>/dev/null || echo 0)
echo "      -> sensitive files: $SENS_COUNT | admin panels: $ADMIN_COUNT | api docs: $API_COUNT | urls with params: $PARAM_COUNT"

# ---------- 4. Re-scan survivors with nuclei ----------
NUCLEI_TXT="$HDIR/nuclei_results.txt"
NUCLEI_JSON="$HDIR/nuclei_results.json"
if [[ -n "$NUCLEI_BIN" && "$ALIVE_COUNT" -gt 0 ]]; then
  echo "[4/4] Re-scanning surviving URLs with nuclei..."
  "$NUCLEI_BIN" -l "$HDIR/alive_urls_clean.txt" \
    -severity low,medium,high,critical \
    -silent \
    -o "$NUCLEI_TXT" \
    -je "$NUCLEI_JSON" || true
  NUCLEI_COUNT=0
  [[ -f "$NUCLEI_JSON" ]] && NUCLEI_COUNT=$(python3 -c "import json,sys
try:
    print(len(json.load(open(sys.argv[1]))))
except Exception:
    print(0)" "$NUCLEI_JSON")
  echo "      -> $NUCLEI_COUNT findings"
else
  echo "[4/4] Skipping nuclei re-scan (nuclei not found or no alive URLs)"
  NUCLEI_COUNT=0
fi

# ---------- Report ----------
{
  echo "# Historical URL triage report"
  echo ""
  echo "- Total historical URLs pulled: **$TOTAL**"
  echo "- Still alive: **$ALIVE_COUNT**"
  echo "- Sensitive files (env/sql/log/backup/config): **$SENS_COUNT**"
  echo "- Admin/internal panels: **$ADMIN_COUNT**"
  echo "- API docs (swagger/graphql): **$API_COUNT**"
  echo "- URLs with parameters (worth manual testing): **$PARAM_COUNT**"
  echo "- Nuclei findings on old endpoints: **$NUCLEI_COUNT**"
  echo ""
  echo "> Every item below is a lead. A URL responding doesn't mean it's"
  echo "> vulnerable or exposed — check each one manually."
  echo ""
  if [[ "$SENS_COUNT" -gt 0 ]]; then
    echo "## ⚠️ Sensitive files (highest priority — check these first)"
    echo '```'
    cat "$OUT_SENSITIVE"
    echo '```'
    echo ""
  fi
  if [[ "$ADMIN_COUNT" -gt 0 ]]; then
    echo "## Admin/internal panels"
    echo '```'
    head -50 "$OUT_ADMIN"
    echo '```'
    echo ""
  fi
  if [[ "$API_COUNT" -gt 0 ]]; then
    echo "## API documentation endpoints"
    echo '```'
    cat "$OUT_API"
    echo '```'
    echo ""
  fi
  echo "## Files in this folder"
  echo "- \`all_urls.txt\` — every historical URL found"
  echo "- \`alive_urls.txt\` — URLs that still respond"
  echo "- \`sensitive_files.txt\`, \`admin_panels.txt\`, \`api_docs.txt\`, \`urls_with_params.txt\` — categorized"
  echo "- \`nuclei_results.txt\`/\`.json\` — vuln scan against surviving URLs"
} > "$OUT_REPORT"

echo
echo "Done. Summary: $OUT_REPORT"
echo "Start with sensitive_files.txt and admin_panels.txt if either is non-empty."