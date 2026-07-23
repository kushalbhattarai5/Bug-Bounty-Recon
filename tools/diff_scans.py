#!/usr/bin/env python3
"""
diff_scans.py — compares two recon.sh output folders and shows what's new.

Usage:
    python3 diff_scans.py <old_scan_dir> <new_scan_dir> [output.md]

Compares:
    subdomains.txt          -> new subdomains
    live_hosts_clean.txt    -> newly live hosts
    nuclei_results.json     -> new findings (by template-id + host)
    takeover_results.json   -> new possible takeovers (if present)
"""
import builtins
import json
import os
import sys


def read_lines(path):
    if not os.path.exists(path):
        return set()
    with open(path, "r", errors="ignore") as f:
        return set(l.strip() for l in f if l.strip())


def read_json_array(path):
    if not os.path.exists(path):
        return []
    try:
        with open(path, "r", errors="ignore") as f:
            content = f.read().strip()
        return json.loads(content) if content else []
    except json.JSONDecodeError:
        return []


def finding_key(item):
    tid = item.get("template-id", "")
    host = item.get("host", "")
    matched = item.get("matched-at", item.get("matched", ""))
    return (tid, host, matched)


def main():
    if len(sys.argv) < 3:
        print("Usage: diff_scans.py <old_scan_dir> <new_scan_dir> [output.md]")
        sys.exit(1)

    old_dir, new_dir = sys.argv[1], sys.argv[2]
    out_path = sys.argv[3] if len(sys.argv) > 3 else os.path.join(new_dir, "diff_since_last.md")

    old_subs = read_lines(os.path.join(old_dir, "subdomains.txt"))
    new_subs = read_lines(os.path.join(new_dir, "subdomains.txt"))
    added_subs = sorted(new_subs - old_subs)
    removed_subs = sorted(old_subs - new_subs)

    old_live = read_lines(os.path.join(old_dir, "live_hosts_clean.txt"))
    new_live = read_lines(os.path.join(new_dir, "live_hosts_clean.txt"))
    added_live = sorted(new_live - old_live)

    old_findings = {finding_key(f): f for f in read_json_array(os.path.join(old_dir, "nuclei_results.json"))}
    new_findings = {finding_key(f): f for f in read_json_array(os.path.join(new_dir, "nuclei_results.json"))}
    added_findings = [f for k, f in new_findings.items() if k not in old_findings]

    old_takeover = {finding_key(f): f for f in read_json_array(os.path.join(old_dir, "takeover_results.json"))}
    new_takeover = {finding_key(f): f for f in read_json_array(os.path.join(new_dir, "takeover_results.json"))}
    added_takeover = [f for k, f in new_takeover.items() if k not in old_takeover]

    lines = []
    lines.append("# Diff since last scan")
    lines.append("")
    lines.append(f"Comparing:\n- old: `{old_dir}`\n- new: `{new_dir}`")
    lines.append("")

    lines.append(f"## New subdomains ({len(added_subs)})")
    lines.append("")
    if added_subs:
        lines.append("```")
        lines.extend(added_subs[:200])
        lines.append("```")
    else:
        lines.append("None.")
    lines.append("")

    if removed_subs:
        lines.append(f"## Subdomains no longer found ({len(removed_subs)})")
        lines.append("")
        lines.append("```")
        lines.extend(removed_subs[:200])
        lines.append("```")
        lines.append("")

    lines.append(f"## Newly live hosts ({len(added_live)})")
    lines.append("")
    if added_live:
        lines.append("```")
        lines.extend(added_live[:200])
        lines.append("```")
    else:
        lines.append("None.")
    lines.append("")

    lines.append(f"## New nuclei findings ({len(added_findings)})")
    lines.append("")
    if added_findings:
        lines.append("| Severity | Template | Host |")
        lines.append("|---|---|---|")
        for f in added_findings:
            sev = f.get("info", {}).get("severity", "unknown")
            name = f.get("info", {}).get("name", f.get("template-id", ""))
            host = f.get("host", "")
            lines.append(f"| {sev} | {name} | {host} |")
    else:
        lines.append("None.")
    lines.append("")

    lines.append(f"## New possible takeovers ({len(added_takeover)})")
    lines.append("")
    if added_takeover:
        for f in added_takeover:
            host = f.get("host", "")
            name = f.get("info", {}).get("name", f.get("template-id", ""))
            lines.append(f"- **{host}** — {name}")
    else:
        lines.append("None.")
    lines.append("")

    with open(out_path, "w") as f:
        f.write("\n".join(lines))

    total_new = len(added_subs) + len(added_live) + len(added_findings) + len(added_takeover)
    print(f"Diff written to {out_path}")
    print(f"Total new items: {total_new}")


if __name__ == "__main__":
    main()
