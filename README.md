# Bug Bounty Recon Tool

Automates the standard authorized bug-bounty recon workflow:

```
subdomains (subfinder) → live hosts (httpx) → open ports (naabu)
  → CVE/misconfig scan (nuclei) → report.md
  → optional: JS secrets, subdomain takeover, 403 bypass, screenshots,
              historical URLs
```

It's a thin orchestrator around well-known, actively maintained open-source
tools (mostly ProjectDiscovery's suite) — it doesn't contain any custom
exploit code. All the actual scanning logic lives in those tools and their
community-maintained templates.

## ⚠️ Scope & legal use

Only run this against domains/IPs you are **explicitly authorized** to
test — targets listed in a bug bounty program's published scope, or systems
you personally own. Running network scans and vulnerability probes against
systems without authorization is illegal in most places (CFAA in the US,
Computer Misuse Act in the UK, and equivalents elsewhere), independent of
intent.

`recon.sh` asks you to re-type the target domain as a confirmation step
before it does anything (unless you pass `-y`) — use that pause to actually
check the program's current scope page. `run_scope.sh` and `schedule.sh`
have their own confirmation steps for multi-target and scheduled runs.

Also worth doing:
- Respect the program's rate limits / out-of-scope exclusions (`-r` slows
  down nuclei if a program asks for it).
- Treat every finding — nuclei matches, JS secret-scan hits, 403-bypass
  flags — as a **lead** to manually verify, not a confirmed bug. False
  positives are normal and expected across every tool here.
- Follow the program's disclosure process for anything you confirm.

## Files

| File | Purpose |
|---|---|
| `install_kali.sh` | One-shot setup for Kali: apt deps, Go, PATH, all tools |
| `install.sh` | Generic (non-Kali) installer, Go tools only |
| `recon.sh` | Core pipeline: subfinder → httpx → naabu → nuclei → report, then offers optional stages |
| `report.py` | Turns raw nuclei/recon output into `report.md`; applies `ignore.txt` |
| `js_analysis.sh` | Crawls JS files from a recon run, scans them for secrets |
| `js_secret_scan.py` | Regex secret/endpoint scanner used by `js_analysis.sh` |
| `takeover_check.sh` | Checks subdomains for possible takeover (dangling CNAMEs) |
| `bypass_403.sh` | Tests 403/401 hosts for access-control bypass |
| `screenshot.sh` | Screenshots every live host (via `gowitness`) |
| `historical_urls.sh` | Pulls archived/historical URLs (via `gau`) |
| `diff_scans.py` | Compares two scans of the same target, shows what's new |
| `notify_webhook.py` | Sends Slack/Discord alert for high/critical findings |
| `run_scope.sh` | Runs `recon.sh` across every domain in a scope file |
| `schedule.sh` | Installs a cron job to run `run_scope.sh` on a schedule |
| `ignore.txt` | List of nuclei template-IDs to suppress from reports |

All scripts expect to live in the **same folder** — they call each other by
relative path.

## Setup (Kali)

```bash
chmod +x *.sh *.py
./install_kali.sh
source ~/.zshrc      # or ~/.bashrc, or open a new terminal
```

This installs apt deps (`libpcap-dev`, `chromium`), Go (if missing),
`subfinder`, `httpx`, `naabu`, `nuclei`, `katana`, `gowitness`, and `gau`;
puts the Go bin directory **first** on your `PATH` (so it takes priority
over unrelated same-named tools, e.g. Python's `httpx` package); grants
`naabu` raw-socket capability so it doesn't need `sudo`; and updates
nuclei's template database.

Verify:
```bash
subfinder -version && httpx -version && naabu -version && nuclei -version && katana -version
```

## Basic usage

```bash
./recon.sh -d example.com
```

You'll be asked to retype the domain to confirm scope, then the pipeline
runs through all four core stages. `recon.sh` resolves each tool by its
explicit install path (not just `PATH` lookup), so it's immune to naming
collisions with unrelated system tools.

### Flags

| Flag | Meaning | Default |
|---|---|---|
| `-d` | Target root domain (required) | — |
| `-o` | Output directory | `results/<domain>_<timestamp>` |
| `-r` | Nuclei rate limit (req/sec) | `150` |
| `-s` | Nuclei severities to include | `low,medium,high,critical` |
| `-y` | Skip the retype-to-confirm prompt **and all** optional-stage prompts | off |

Use `-y` only once you've already verified scope for that target — it's
meant for repeat runs or scripted/scheduled use, not first-time scans.

Example, slower/stealthier scan on medium+ severity only:
```bash
./recon.sh -d example.com -r 50 -s medium,high,critical
```

## Optional follow-up stages

After the core scan + report, `recon.sh` asks yes/no for each of these in
turn — type `y` to run it immediately against the results you just got, or
`n` to skip (with the exact command shown so you can run it later):

| Tool | What it checks | Notes |
|---|---|---|
| `js_analysis.sh` | JS files for leaked API keys, tokens, internal endpoints | Downloads JS locally, regex-scans it |
| `takeover_check.sh` | Dangling CNAMEs pointing at unclaimed cloud resources | Checks the full subdomain list, not just live hosts |
| `bypass_403.sh` | Whether 403/401-protected pages can be bypassed via headers/paths/methods | Only uses safe methods (GET/HEAD/OPTIONS) — never PUT/DELETE/PATCH |
| `screenshot.sh` | Visual screenshot of every live host | Needs Chromium (installed by `install_kali.sh`) |
| `historical_urls.sh` | Old/archived URLs that still work but aren't linked live | Pulled from Wayback Machine via `gau` |

If none of your live hosts match a check's condition (e.g. no 403/401
responses that run), the tool just reports "nothing found" — that's a
normal, correct result, not an error.

Each can also be run standalone, any time, against a past results folder:
```bash
./js_analysis.sh results/example.com_20260713_063600
./takeover_check.sh results/example.com_20260713_063600
./bypass_403.sh results/example.com_20260713_063600
./screenshot.sh results/example.com_20260713_063600
./historical_urls.sh results/example.com_20260713_063600
```

## Output

```
results/example.com_20260713_063600/
├── subdomains.txt              # raw subfinder output
├── live_hosts.txt              # httpx output: status code, title, tech stack
├── live_hosts_clean.txt        # just the URLs, used as input to nuclei
├── naabu_targets.txt           # bare hostnames (no scheme), used as input to naabu
├── ports.txt                   # naabu open host:port pairs
├── nuclei_results.txt          # nuclei findings, human-readable/colored
├── nuclei_results.json         # same findings, structured JSON (used by report.py)
├── report.md                   # human-readable summary, grouped by severity
├── js/                         # if you ran js_analysis.sh
│   ├── js_urls.txt
│   ├── endpoints.txt
│   ├── files/
│   └── js_findings.md
├── takeover_results.txt/.json  # if you ran takeover_check.sh
├── bypass_403_results.md       # if you ran bypass_403.sh
├── screenshots/                # if you ran screenshot.sh
└── historical_urls.txt / historical_urls_interesting.txt   # if you ran historical_urls.sh
```

Open `report.md` first. **Always manually verify findings** before
reporting anything — every tool here produces leads, not confirmed bugs.

## Multi-target scans

Create a `scope.txt` with one authorized root domain per line:
```
example.com
api.example.org
# out of scope, left commented:
# internal.example.com
```

Then:
```bash
./run_scope.sh scope.txt results
```

This confirms the **entire list** once (instead of prompting per domain),
then loops `recon.sh` over every target and writes a `summary.md` linking
to each target's individual report.

## Comparing scans & alerts

```bash
python3 diff_scans.py results/example.com_OLD results/example.com_NEW
```
Shows new subdomains, newly-live hosts, new nuclei findings, and new
takeover matches since the last scan of the same target.

```bash
python3 notify_webhook.py results/example.com_<date> <webhook_url> --min-severity high
```
Sends a Slack (default) or Discord (`--format discord`) message only if
there's a finding at or above the severity you set. Silent if nothing
qualifies.

## Ignoring known false positives

Edit `ignore.txt` in this folder — one nuclei `template-id` per line,
`#` for comments:
```
weak-cipher-suites
missing-security-headers
```
`report.py` automatically filters these out of `report.md` (they're still
in the raw `nuclei_results.json`, just hidden from the summary). This list
is shared across all targets.

## Scheduled / unattended scanning

For ongoing monitoring of a program's scope (e.g. catching newly added
subdomains over time):

```bash
./schedule.sh scope.txt results "0 3 * * *"   # daily at 3am
```

Asks you to explicitly confirm — at setup time — that everything in
`scope.txt` is authorized for **ongoing, unattended** scanning, since cron
runs won't be there for you to confirm each time. Logs land in `logs/`.
Remove the job later with `crontab -e`.

**Important:** unattended scanning only stays legitimate if you keep
`scope.txt` in sync with the program's actual current scope. Bug bounty
programs add/remove domains — re-check periodically rather than "set and
forget" indefinitely.

## Common issues

**`httpx` errors like "No such option: -l"** — Kali sometimes has a
*different* `httpx` (a Python HTTP client library) installed system-wide,
which can shadow the real ProjectDiscovery tool if `PATH` order is wrong.
`recon.sh` resolves tools by explicit path to avoid this, but if you're
calling `httpx` directly outside the script, check `which -a httpx` and use
the full path to the one under `$(go env GOPATH)/bin`.

**`naabu`: "no valid ipv4 or ipv6 targets were found"** — naabu needs bare
hostnames, not full URLs. `recon.sh` already generates `naabu_targets.txt`
(scheme/path stripped) for this; if you're running naabu manually, make
sure your input list doesn't have `https://` prefixes.

**nuclei printing raw JSON instead of readable colored output** — caused by
the `-jsonl` flag, which redirects *all* output to JSON. `recon.sh` uses
`-o` (readable/colored) plus `-je` (separate JSON export for `report.py`)
instead.

**`gowitness` "unknown flag" errors** — flag names occasionally change
between versions; `screenshot.sh` uses `--write-jsonl-file`, not
`--jsonl-file`. If you hit a similar error, run `gowitness scan file --help`
to check current flag names for your installed version.

**A follow-up stage says "not found" after answering `y`** — that script
isn't in the same folder as `recon.sh`, or isn't executable. Check with
`ls -la <script>.sh` and `chmod +x <script>.sh` if needed.

**A follow-up stage says "nothing found"** — that's a normal, correct
result when the condition just doesn't apply this run (e.g. no hosts
returned 403, so there was nothing for `bypass_403.sh` to test). Not a bug.

## Extending it

- Narrow/broaden nuclei coverage with `-tags` inside `recon.sh` (e.g.
  `-tags cve,exposure`).
- Swap `naabu -top-ports 1000` for `-p -` (all ports) if the program's
  rules allow full port sweeps — much slower.
- Add a new optional stage by writing a script that takes a results folder
  as its argument, then add one line to the `OPTIONAL_STAGES` array near
  the end of `recon.sh` — it'll automatically get its own yes/no prompt.