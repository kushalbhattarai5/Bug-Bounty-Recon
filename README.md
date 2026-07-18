# Bug Bounty Recon Tool

Automates the first steps of bug bounty hunting: finds subdomains, checks
which are online, scans ports, scans for known vulnerabilities, and more.
Ends with a report you review yourself — it doesn't decide what's a real
bug for you.

## ⚠️ Only scan what you're allowed to

Only use this on a company's official bug bounty scope, or something you
own. Scanning without permission can be illegal. The tool asks you to
confirm the target before starting — that's your cue to double-check scope.

## Setup (once)

```bash
chmod +x *.sh *.py
./install_kali.sh
```

## Scan one target

```bash
./recon.sh -d example.com
```

Type the domain again when asked, to confirm. It runs on its own after
that — takes a few minutes. At the end it asks if you also want to check
JS files for leaked info, and check for subdomain takeovers (`y`/`n` each).

**Results:** `results/example.com_<date>/report.md`

## Scan multiple targets

Make `scope.txt`, one domain per line:
```
example.com
api.example.com
```
Then:
```bash
./run_scope.sh scope.txt results
```
Confirms once, then scans every domain in the list.

## Extra tools (run manually, after a scan)

| Tool | What it does | How to run |
|---|---|---|
| `js_analysis.sh` | Scans JS files for leaked keys/tokens | `./js_analysis.sh results/target_<date>` |
| `takeover_check.sh` | Checks for dangling subdomains that can be hijacked | `./takeover_check.sh results/target_<date>` |
| `screenshot.sh` | Screenshots every live host so you can skim visually | `./screenshot.sh results/target_<date>` |
| `historical_urls.sh` | Finds old URLs (Wayback Machine) that still work | `./historical_urls.sh results/target_<date>` |
| `diff_scans.py` | Shows what's new between two scans of the same target | `python3 diff_scans.py results/OLD results/NEW` |
| `notify_webhook.py` | Sends Slack/Discord alert for high/critical findings | `python3 notify_webhook.py results/target_<date> <webhook_url>` |

## Ignoring known false positives

Edit `ignore.txt` and add one finding type per line (the `template-id` from
a finding you've already checked and decided isn't useful). Future reports
will automatically hide matches for anything listed there.

## Scheduled scanning

For ongoing monitoring of a program's scope:
```bash
./schedule.sh scope.txt results "0 3 * * *"   # daily at 3am
```
Confirms once at setup that everything in `scope.txt` is authorized for
ongoing automated scanning. Keep that file in sync with the program's
actual scope — don't "set and forget" indefinitely.

## Keep in mind

- Findings are leads, not confirmed bugs — always double-check by hand.
- JS scan and historical URL results especially have false alarms.
- Big targets take longer — that's normal.
