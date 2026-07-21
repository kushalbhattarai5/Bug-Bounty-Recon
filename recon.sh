#!/usr/bin/env bash
#
# recon.sh — authorized bug bounty recon + vuln scan pipeline
#
# ============================================================================
# LEGAL / SCOPE WARNING
# Only run this against targets you are explicitly authorized to test
# (e.g. domains listed in a bug bounty program's scope, with permission).
# Unauthorized scanning of systems you don't own or have written permission
# to test is illegal in most jurisdictions (e.g. under the US CFAA, UK
# Computer Misuse Act, etc.) regardless of intent.
# ============================================================================
#
# Core pipeline:
#   1. subfinder  -> passive subdomain enumeration
#   2. httpx      -> probe which hosts are alive (HTTP/S), grab metadata
#   3. naabu      -> fast port scan on live hosts
#   4. nuclei     -> template-based scanning for known CVEs & misconfigs
#   then report.py builds report.md, and priority_score.py ranks hosts
#
# Optional modules (modules/): JS secret scan, subdomain takeover check,
# 403 bypass check, screenshots, historical URL triage.
#
# Usage:
#   ./recon.sh -d target.com [options]
#
# Run ./recon.sh -h for all options.
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ---------- load defaults from config.sh, if present ----------
NUCLEI_RATE=150
SEVERITY="low,medium,high,critical"
WEBHOOK_URL=""
WEBHOOK_SEVERITY="high"
[[ -f "$SCRIPT_DIR/config.sh" ]] && source "$SCRIPT_DIR/config.sh"
NUCLEI_RATE="${DEFAULT_NUCLEI_RATE:-$NUCLEI_RATE}"
SEVERITY="${DEFAULT_SEVERITY:-$SEVERITY}"
WEBHOOK_URL="${DEFAULT_WEBHOOK_URL:-$WEBHOOK_URL}"
WEBHOOK_SEVERITY="${DEFAULT_WEBHOOK_SEVERITY:-$WEBHOOK_SEVERITY}"

# ---------- flags ----------
TARGET=""
OUTDIR=""
THREADS=50
AUTO=false   # -y: no prompts at all — confirm scope once, then run everything

usage() {
  echo "Usage: $0 -d <domain> [-o <output_dir>] [-r <nuclei_rate>] [-s <severities>] [-y] [-w <webhook_url>]"
  echo "  -d   Root domain to recon (must be in-scope for your authorization)"
  echo "  -o   Output directory (default: results/<domain>_<timestamp>, or"
  echo "       resumes an incomplete previous scan of the same domain if found)"
  echo "  -r   Nuclei requests/sec rate limit (default from config.sh: $NUCLEI_RATE)"
  echo "  -s   Comma-separated nuclei severities (default from config.sh: $SEVERITY)"
  echo "  -y   No prompts: confirm scope once, then run every optional module"
  echo "       automatically and finish unattended. Use only once you've"
  echo "       already verified scope for this target."
  echo "  -w   Webhook URL for high/critical alerts (default from config.sh"
  echo "       if set there). Sends nothing if nothing qualifies."
  echo
  echo "Edit config.sh to set your usual defaults so you don't have to pass"
  echo "these flags every time."
  exit 1
}

while getopts "d:o:r:s:yw:h" opt; do
  case $opt in
    d) TARGET="$OPTARG" ;;
    o) OUTDIR="$OPTARG" ;;
    r) NUCLEI_RATE="$OPTARG" ;;
    s) SEVERITY="$OPTARG" ;;
    y) AUTO=true ;;
    w) WEBHOOK_URL="$OPTARG" ;;
    h) usage ;;
    *) usage ;;
  esac
done

[[ -z "$TARGET" ]] && usage

# ---------- shared yes/no prompt (also used for resume + optional modules) ----------
ask_yes_no() {
  local prompt="$1" answer
  if [[ "$AUTO" == true ]]; then
    echo "$prompt (auto-yes — running with -y)"
    return 0
  fi
  while true; do
    read -r -p "$prompt [y/n]: " answer
    case "$answer" in
      [Yy]|[Yy][Ee][Ss]) return 0 ;;
      [Nn]|[Nn][Oo]) return 1 ;;
      *) echo "Please type yes or no." ;;
    esac
  done
}

# ---------- pick output dir, offering to resume an incomplete scan ----------
TS=$(date +%Y%m%d_%H%M%S)
if [[ -z "$OUTDIR" ]]; then
  # FIX: under `set -e` + `set -o pipefail`, this pipeline can legitimately
  # return non-zero (e.g. `ls` finds no matching dirs on a first-ever run),
  # which used to kill the whole script silently before any banner text
  # was printed. Make sure results/ exists first (so `ls` doesn't error),
  # and guard the pipeline with `|| true` so a no-match result is never
  # treated as fatal.
  mkdir -p results
  LATEST_INCOMPLETE=$(
    { ls -td "results/${TARGET}"_*/ 2>/dev/null || true; } | while read -r d; do
      [[ -f "$d/.done_nuclei" ]] || echo "$d"
    done | head -n1
  ) || true
  LATEST_INCOMPLETE="${LATEST_INCOMPLETE%/}"

  if [[ -n "$LATEST_INCOMPLETE" ]]; then
    echo "Found an incomplete previous scan: $LATEST_INCOMPLETE"
    if ask_yes_no "Resume it instead of starting a new scan?"; then
      OUTDIR="$LATEST_INCOMPLETE"
    else
      OUTDIR="results/${TARGET}_${TS}"
    fi
  else
    OUTDIR="results/${TARGET}_${TS}"
  fi
fi
mkdir -p "$OUTDIR"

echo "=============================================="
echo " Target        : $TARGET"
echo " Output dir    : $OUTDIR"
echo " Nuclei rate   : $NUCLEI_RATE req/s"
echo " Severities    : $SEVERITY"
echo " Mode          : $([[ "$AUTO" == true ]] && echo 'full auto (-y)' || echo 'interactive')"
echo "=============================================="
echo

# ---------- scope confirmation (once, always — even with -y) ----------
if [[ "$AUTO" == true ]]; then
  echo "!! Running with -y: make sure you've already verified $TARGET is in scope. !!"
else
  echo "!! Confirm this target is in your authorized scope before continuing. !!"
  read -r -p "Type the target domain again to confirm and proceed: " CONFIRM
  if [[ "$CONFIRM" != "$TARGET" ]]; then
    echo "Confirmation did not match target. Aborting."
    exit 1
  fi
fi

# ---------- resolve tools by explicit path ----------
# Kali (and other distros) sometimes have unrelated tools with the same name
# on PATH (e.g. the Python "httpx" HTTP client library CLI collides with
# ProjectDiscovery's Go "httpx" recon tool). Prefer the Go-installed binary
# by explicit path so we never accidentally run the wrong "httpx".
GOBIN="$(go env GOPATH 2>/dev/null)/bin"

resolve_tool() {
  local name="$1"
  if [[ -x "$GOBIN/$name" ]]; then
    echo "$GOBIN/$name"
  else
    command -v "$name" 2>/dev/null || true
  fi
}

SUBFINDER_BIN=$(resolve_tool subfinder)
HTTPX_BIN=$(resolve_tool httpx)
NAABU_BIN=$(resolve_tool naabu)
NUCLEI_BIN=$(resolve_tool nuclei)

check_tool() {
  local name="$1" path="$2"
  if [[ -z "$path" ]]; then
    echo "[!] Missing required tool: $name"
    echo "    Run ./install_kali.sh first, or see https://github.com/projectdiscovery/$name"
    exit 1
  fi
}
check_tool subfinder "$SUBFINDER_BIN"
check_tool httpx "$HTTPX_BIN"
check_tool naabu "$NAABU_BIN"
check_tool nuclei "$NUCLEI_BIN"

echo "Using tools:"
echo "  subfinder: $SUBFINDER_BIN"
echo "  httpx:     $HTTPX_BIN"
echo "  naabu:     $NAABU_BIN"
echo "  nuclei:    $NUCLEI_BIN"

# ---------- 1. Subdomain enumeration ----------
if [[ -f "$OUTDIR/.done_subfinder" ]]; then
  echo "[1/4] Subfinder already completed for this output dir — skipping"
else
  echo "[1/4] Enumerating subdomains with subfinder..."
  "$SUBFINDER_BIN" -d "$TARGET" -silent -all -o "$OUTDIR/subdomains.txt"
  touch "$OUTDIR/.done_subfinder"
fi
SUB_COUNT=$(wc -l < "$OUTDIR/subdomains.txt" 2>/dev/null || echo 0)
echo "      -> $SUB_COUNT subdomains found"

# ---------- 2. Live host probing ----------
if [[ -f "$OUTDIR/.done_httpx" ]]; then
  echo "[2/4] httpx already completed for this output dir — skipping"
else
  echo "[2/4] Probing for live hosts with httpx..."
  "$HTTPX_BIN" -l "$OUTDIR/subdomains.txt" -silent -follow-redirects \
    -status-code -title -tech-detect -threads "$THREADS" \
    -o "$OUTDIR/live_hosts.txt"
  touch "$OUTDIR/.done_httpx"
fi
LIVE_COUNT=$(wc -l < "$OUTDIR/live_hosts.txt" 2>/dev/null || echo 0)
echo "      -> $LIVE_COUNT live hosts"

awk '{print $1}' "$OUTDIR/live_hosts.txt" > "$OUTDIR/live_hosts_clean.txt"

# naabu needs bare hostnames/IPs, not full URLs with scheme+path — strip those
sed -E 's#^https?://##; s#/.*$##; s#:[0-9]+$##' "$OUTDIR/live_hosts_clean.txt" \
  | sort -u > "$OUTDIR/naabu_targets.txt"

# ---------- 3. Port scanning ----------
if [[ -f "$OUTDIR/.done_naabu" ]]; then
  echo "[3/4] naabu already completed for this output dir — skipping"
else
  echo "[3/4] Scanning ports with naabu..."
  "$NAABU_BIN" -list "$OUTDIR/naabu_targets.txt" -silent \
    -top-ports 1000 -o "$OUTDIR/ports.txt" || true
  touch "$OUTDIR/.done_naabu"
fi
PORT_COUNT=0
[[ -f "$OUTDIR/ports.txt" ]] && PORT_COUNT=$(wc -l < "$OUTDIR/ports.txt")
echo "      -> $PORT_COUNT open host:port pairs"

# ---------- 4. Vulnerability / misconfig scanning ----------
if [[ -f "$OUTDIR/.done_nuclei" ]]; then
  echo "[4/4] nuclei already completed for this output dir — skipping"
else
  echo "[4/4] Running nuclei templates (CVEs + misconfigs)..."
  "$NUCLEI_BIN" -l "$OUTDIR/live_hosts_clean.txt" \
    -severity "$SEVERITY" \
    -rate-limit "$NUCLEI_RATE" \
    -silent \
    -o "$OUTDIR/nuclei_results.txt" \
    -je "$OUTDIR/nuclei_results.json" || true
  touch "$OUTDIR/.done_nuclei"
fi
FINDINGS=0
if [[ -f "$OUTDIR/nuclei_results.json" ]]; then
  FINDINGS=$(python3 -c "import json,sys
try:
    print(len(json.load(open(sys.argv[1]))))
except Exception:
    print(0)" "$OUTDIR/nuclei_results.json")
fi
echo "      -> $FINDINGS findings"

# ---------- report ----------
echo
echo "Generating report..."
python3 "$SCRIPT_DIR/report.py" "$OUTDIR"
echo "Report: $OUTDIR/report.md"

# ---------- optional modules ----------
echo
echo "Optional modules available. Type y to run one now, n to skip"
echo "(you can always run it manually later)."

# name | script | description
OPTIONAL_MODULES=(
  "js_analysis.sh|Analyze JS files for leaked keys/tokens"
  "takeover_check.sh|Check for subdomain takeovers"
  "bypass_403.sh|Check 403/401 hosts for access-control bypass"
  "screenshot.sh|Screenshot every live host"
  "historical_urls.sh|Pull + triage historical/archived URLs"
)

for stage in "${OPTIONAL_MODULES[@]}"; do
  script="${stage%%|*}"
  desc="${stage#*|}"
  echo
  if ask_yes_no "Run '$script' now? ($desc)"; then
    if [[ -x "$SCRIPT_DIR/modules/$script" ]]; then
      "$SCRIPT_DIR/modules/$script" "$OUTDIR"
    else
      echo "[!] modules/$script not found or not executable — skipping"
    fi
  else
    echo "Skipped. Run it later with: ./modules/$script $OUTDIR"
  fi
done

# ---------- priority score (always runs — cheap, ties everything together) ----------
if [[ -x "$SCRIPT_DIR/priority_score.py" ]]; then
  echo
  echo "Building priority list from everything that ran..."
  python3 "$SCRIPT_DIR/priority_score.py" "$OUTDIR" || true
fi

# ---------- webhook notification (only if a webhook URL is set) ----------
if [[ -n "$WEBHOOK_URL" && -x "$SCRIPT_DIR/tools/notify_webhook.py" ]]; then
  echo
  echo "Checking if anything qualifies for a webhook alert (severity >= $WEBHOOK_SEVERITY)..."
  python3 "$SCRIPT_DIR/tools/notify_webhook.py" "$OUTDIR" "$WEBHOOK_URL" --min-severity "$WEBHOOK_SEVERITY" || true
fi

echo
echo "Done. Final results in: $OUTDIR"
echo "Report:   $OUTDIR/report.md"
echo "Priority: $OUTDIR/priority.md"