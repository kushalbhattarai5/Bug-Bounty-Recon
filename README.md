# Bug Bounty Recon & Vuln-Scan Pipeline

Automates the standard authorized bug-bounty recon workflow:

```
subdomains (subfinder) → live hosts (httpx) → open ports (naabu) → CVE/misconfig scan (nuclei) → report.md
```

It's a thin orchestrator around four well-known, actively maintained
open-source tools from ProjectDiscovery — it doesn't contain any custom
exploit code. All the actual scanning logic lives in those tools and their
community-maintained templates.

## ⚠️ Scope & legal use

Only run this against domains/IPs you are **explicitly authorized** to test —
i.e. targets listed in a bug bounty program's published scope, or systems you
personally own. Running network scans and vulnerability probes against
systems without authorization is illegal in most places (CFAA in the US,
Computer Misuse Act in the UK, and equivalents elsewhere), independent of
intent. `recon.sh` will ask you to re-type the target domain as a
confirmation step before it does anything — use that pause to actually check
the program's scope page.

Also worth doing:
- Respect the program's rate limits / out-of-scope exclusions (use `-r` to
  slow down nuclei if the program asks for it).
- Don't run active exploitation beyond what nuclei's detection templates do —
  this tool is for *finding and confirming*, not exploiting further.
- Follow the program's disclosure process for anything you find.

## Setup

1. Install Go 1.21+: https://go.dev/dl/
2. Run the installer:
   ```
   chmod +x install.sh recon.sh
   ./install.sh
   ```
3. (Optional but recommended) Add a subfinder API key config for better
   subdomain coverage — see
   https://github.com/projectdiscovery/subfinder#post-installation-instructions

## Usage

```bash
./recon.sh -d example.com
```

Options:

| Flag | Meaning | Default |
|---|---|---|
| `-d` | Target root domain (required) | — |
| `-o` | Output directory | `results/<domain>_<timestamp>` |
| `-r` | Nuclei rate limit (req/sec) | `150` |
| `-s` | Nuclei severities to include | `low,medium,high,critical` |

Example, slower/stealthier scan on medium+ severity only:

```bash
./recon.sh -d example.com -r 50 -s medium,high,critical
```

## Output

```
results/example.com_20260713_063600/
├── subdomains.txt        # raw subfinder output
├── live_hosts.txt        # httpx output: status code, title, tech stack
├── live_hosts_clean.txt  # just the URLs, used as input to naabu/nuclei
├── ports.txt             # naabu open host:port pairs
├── nuclei_results.jsonl  # raw nuclei findings, one JSON object per line
└── report.md             # human-readable summary, grouped by severity
```

Open `report.md` for a readable summary you can review before writing up a
submission. **Always manually verify findings** — nuclei templates can and do
produce false positives.

## Kali Linux: full automation

For Kali specifically, three extra scripts handle setup, multi-target runs,
and scheduling so you don't have to babysit each step:

### 1. One-shot setup

```bash
chmod +x install_kali.sh recon.sh run_scope.sh schedule.sh report.py
./install_kali.sh
source ~/.bashrc   # or open a new terminal
```

This installs apt deps (`libpcap-dev`), Go (if missing), all four
ProjectDiscovery tools, sets your `PATH`, grants `naabu` raw-socket
capability so it doesn't need `sudo` for SYN scans, and updates nuclei's
template database.

### 2. Scan a whole scope, not just one domain

Create a `scope.txt` with one authorized root domain per line:

```
example.com
api.example.org
# out of scope, left commented:
# internal.example.com
```

Then run:

```bash
./run_scope.sh scope.txt results
```

This asks you to confirm the **entire list** once (instead of prompting per
domain), then loops `recon.sh` over every target and writes a
`summary.md` linking to each target's individual report.

### 3. Scheduled / unattended scanning

If you want ongoing monitoring of a program's scope (e.g. to catch newly
added subdomains over time), `schedule.sh` installs a cron job for you:

```bash
./schedule.sh scope.txt results "0 3 * * *"   # daily at 3am
```

It asks you to explicitly confirm — at the moment you set up the schedule —
that everything in `scope.txt` is authorized for **ongoing, unattended**
scanning, since cron runs won't be there for you to confirm each time.
Logs land in `logs/`. Remove the job later with `crontab -e`.

**Important:** unattended scanning only stays legitimate if you keep
`scope.txt` in sync with the program's actual current scope. Bug bounty
programs add/remove domains; re-check periodically rather than "set and
forget" indefinitely.

## Extending it

- Add more nuclei template categories with `-nuclei-args "-tags cve,exposure"`
  style flags inside `recon.sh` if you want to narrow/broaden coverage.
- Swap `naabu -top-ports 1000` for `-p -` (all ports) if the program's rules
  allow full port sweeps — it's much slower.
- Pipe `live_hosts_clean.txt` into other authorized tools you already use
  (e.g. content discovery, JS endpoint extraction) by adding a stage.
