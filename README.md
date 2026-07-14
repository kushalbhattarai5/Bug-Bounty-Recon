# Bug Bounty Recon Tool

This tool automates the boring first steps of bug bounty hunting:

1. Find a target's subdomains
2. Check which ones are actually online
3. Scan for open ports
4. Scan for known vulnerabilities and misconfigurations
5. (Optional) Pull out JS files and check them for leaked keys/tokens

At the end, it gives you a clean report to read — you still review it and
decide what's worth digging into further.

## ⚠️ Before you use this

Only scan domains you're allowed to test — a company's official bug bounty
program scope, or something you personally own. Scanning a company without
permission can be illegal, even if you don't mean any harm. The tool will
ask you to confirm the target before it starts, as a reminder to double
check.

## Setup (one time only)

Open a terminal in this folder and run:

```bash
chmod +x *.sh *.py
./install_kali.sh
source ~/.zshrc
```

This installs everything the tool needs. Wait for it to finish — it can
take a few minutes.

## How to scan one website

```bash
./recon.sh -d example.com
```

Replace `example.com` with your target. It will ask you to type the domain
name again to confirm — this is just a safety check, type it and press
Enter.

Then it runs automatically through all the steps. This can take a few
minutes depending on how big the target is.

At the end, it will ask:

```
Do you want to analyze JS files for this target now? [y/n]:
```

Type `y` and press Enter if you want it to also check JS files for leaked
info, or `n` to skip that for now.

## Where to find your results

Everything is saved in a new folder inside `results/`. The one file you
mainly want to open is:

```
results/example.com_<date>/report.md
```

Open it in any text editor. It lists everything found, sorted by how
serious it is.

## Scanning multiple websites at once

Make a text file called `scope.txt`, one domain per line:

```
example.com
api.example.com
```

Then run:

```bash
./run_scope.sh scope.txt results
```

It will ask you to confirm once, then scan every domain in the list
automatically.

## A few things to remember

- **Not everything it finds is a real bug.** Treat results as things to
  double-check yourself, not confirmed problems.
- **JS scan results especially** can have false alarms — a random bit of
  code can look like a leaked key even when it isn't.
- If a scan is taking a long time, that's normal for big targets — just
  let it run.

## If something breaks

- `httpx` gives a weird error → run `which -a httpx` and make sure the
  right one is being used. The tool already tries to handle this for you.
- `naabu` says no valid targets found → this is fixed in the current
  version of the script, make sure you're using the latest file.
- Nuclei prints unreadable text instead of clean results → same, fixed in
  the current version.

If you're ever unsure whether something is working right, just copy the
error message and ask for help.