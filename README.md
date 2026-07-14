# Bug Bounty Recon Tool

Automates the first steps of bug bounty hunting: finds subdomains, checks
which are online, scans ports, scans for known vulnerabilities, and
(optionally) checks JS files for leaked keys. Ends with a report you review
yourself — it doesn't decide what's a real bug for you.

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

Type the domain again when asked, to confirm. It then runs on its own —
takes a few minutes. At the end it asks if you also want to check JS files
for leaked info (`y`/`n`).

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

## Keep in mind

- Findings are leads, not confirmed bugs — always double-check by hand.
- JS scan results especially have false alarms.
- Big targets take longer — that's normal.
