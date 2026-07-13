#!/usr/bin/env bash
# schedule.sh — sets up a cron job to run run_scope.sh on a recurring schedule.
#
# This is for continuous monitoring of a bug bounty program's scope
# (e.g. catching newly-added subdomains/hosts over time).
#
# Usage:
#   ./schedule.sh <scope_file> <output_base_dir> <cron_schedule>
#
# Examples:
#   ./schedule.sh scope.txt results "0 3 * * *"      # daily at 3am
#   ./schedule.sh scope.txt results "0 3 * * 0"      # weekly, Sunday 3am
#
set -euo pipefail

SCOPE_FILE="${1:-}"
OUTBASE="${2:-results}"
CRON_SCHEDULE="${3:-}"

if [[ -z "$SCOPE_FILE" || -z "$CRON_SCHEDULE" ]]; then
  echo "Usage: $0 <scope_file> <output_base_dir> <cron_schedule>"
  echo "  e.g. $0 scope.txt results \"0 3 * * *\"   # daily at 3am"
  exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCOPE_FILE_ABS="$(cd "$(dirname "$SCOPE_FILE")" && pwd)/$(basename "$SCOPE_FILE")"
LOG_DIR="$SCRIPT_DIR/logs"
mkdir -p "$LOG_DIR"

# Since run_scope.sh normally asks for interactive confirmation, cron runs
# need a non-interactive variant. We pipe "YES" in automatically here —
# meaning YOU are confirming right now, at schedule-setup time, that every
# domain in $SCOPE_FILE is authorized for ongoing automated scanning.
CRON_CMD="echo YES | $SCRIPT_DIR/run_scope.sh $SCOPE_FILE_ABS $OUTBASE >> $LOG_DIR/cron_\$(date +\\%Y\\%m\\%d).log 2>&1"

CRON_LINE="$CRON_SCHEDULE $CRON_CMD"

echo "About to install this cron job:"
echo "  $CRON_LINE"
echo
echo "This means the pipeline will run unattended on the schedule above"
echo "against every domain in: $SCOPE_FILE_ABS"
read -r -p "Confirm all targets remain authorized for ongoing scanning. Type YES: " CONFIRM
if [[ "$CONFIRM" != "YES" ]]; then
  echo "Not confirmed. Aborting."
  exit 1
fi

(crontab -l 2>/dev/null || true; echo "$CRON_LINE") | crontab -

echo "Cron job installed. View with: crontab -l"
echo "Logs will be written to: $LOG_DIR"
echo "To remove later: crontab -e   (then delete the matching line)"
