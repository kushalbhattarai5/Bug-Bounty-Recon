#!/usr/bin/env python3
"""
report.py — turns raw recon.sh output into a readable markdown report.

Usage:
    python3 report.py <output_dir>

Reads (if present):
    <output_dir>/subdomains.txt
    <output_dir>/live_hosts.txt
    <output_dir>/ports.txt
    <output_dir>/nuclei_results.jsonl

Writes:
    <output_dir>/report.md
"""
import json
import sys
import os
from collections import defaultdict
from datetime import datetime

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info", "unknown"]


def read_lines(path):
    if not os.path.exists(path):
        return []
    with open(path, "r", errors="ignore") as f:
        return [l.strip() for l in f if l.strip()]


def read_json_array(path):
    if not os.path.exists(path):
        return []
    with open(path, "r", errors="ignore") as f:
        content = f.read().strip()
    if not content:
        return []
    try:
        data = json.loads(content)
        return data if isinstance(data, list) else [data]
    except json.JSONDecodeError:
        return []


def read_ignore_list(path):
    ignored = set()
    if os.path.exists(path):
        with open(path, "r", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    ignored.add(line)
    return ignored


def main():
    if len(sys.argv) < 2:
        print("Usage: report.py <output_dir> [ignore_file]")
        sys.exit(1)

    outdir = sys.argv[1]
    script_dir = os.path.dirname(os.path.abspath(__file__))
    ignore_path = sys.argv[2] if len(sys.argv) > 2 else os.path.join(script_dir, "ignore.txt")
    ignored_templates = read_ignore_list(ignore_path)

    subdomains = read_lines(os.path.join(outdir, "subdomains.txt"))
    live_hosts = read_lines(os.path.join(outdir, "live_hosts.txt"))
    ports = read_lines(os.path.join(outdir, "ports.txt"))
    all_findings = read_json_array(os.path.join(outdir, "nuclei_results.json"))

    suppressed_count = sum(1 for f in all_findings if f.get("template-id", "") in ignored_templates)
    findings = [f for f in all_findings if f.get("template-id", "") not in ignored_templates]

    # group findings by severity
    by_sev = defaultdict(list)
    for f in findings:
        sev = f.get("info", {}).get("severity", "unknown").lower()
        by_sev[sev].append(f)

    lines = []
    lines.append(f"# Recon & Vulnerability Scan Report")
    lines.append("")
    lines.append(f"Generated: {datetime.now().isoformat(timespec='seconds')}")
    lines.append("")
    lines.append("> Scope reminder: this report should only ever be shared/used")
    lines.append("> for targets you were authorized to test.")
    lines.append("")
    lines.append("## Summary")
    lines.append("")
    lines.append(f"- Subdomains discovered: **{len(subdomains)}**")
    lines.append(f"- Live hosts: **{len(live_hosts)}**")
    lines.append(f"- Open host:port pairs: **{len(ports)}**")
    lines.append(f"- Total nuclei findings: **{len(findings)}**")
    if suppressed_count:
        lines.append(f"  - ({suppressed_count} suppressed via ignore.txt)")
    for sev in SEVERITY_ORDER:
        if by_sev.get(sev):
            lines.append(f"  - {sev.capitalize()}: {len(by_sev[sev])}")
    lines.append("")

    lines.append("## Findings by Severity")
    lines.append("")
    if not findings:
        lines.append("No nuclei findings recorded.")
    for sev in SEVERITY_ORDER:
        items = by_sev.get(sev)
        if not items:
            continue
        lines.append(f"### {sev.capitalize()} ({len(items)})")
        lines.append("")
        lines.append("| Template | Host | Matched At | Description |")
        lines.append("|---|---|---|---|")
        for item in items:
            info = item.get("info", {})
            name = info.get("name", item.get("template-id", "unknown"))
            host = item.get("host", "")
            matched = item.get("matched-at", item.get("matched", ""))
            desc = (info.get("description") or "").replace("\n", " ").replace("|", "-")
            if len(desc) > 100:
                desc = desc[:97] + "..."
            lines.append(f"| {name} | {host} | {matched} | {desc} |")
        lines.append("")

    lines.append("## Live Hosts")
    lines.append("")
    if live_hosts:
        lines.append("```")
        lines.extend(live_hosts[:200])
        if len(live_hosts) > 200:
            lines.append(f"... and {len(live_hosts) - 200} more (see live_hosts.txt)")
        lines.append("```")
    else:
        lines.append("No live hosts recorded.")
    lines.append("")

    lines.append("## Open Ports")
    lines.append("")
    if ports:
        lines.append("```")
        lines.extend(ports[:200])
        if len(ports) > 200:
            lines.append(f"... and {len(ports) - 200} more (see ports.txt)")
        lines.append("```")
    else:
        lines.append("No open ports recorded.")
    lines.append("")

    lines.append("## Next Steps")
    lines.append("")
    lines.append("- Manually verify each finding before reporting — nuclei templates")
    lines.append("  can produce false positives.")
    lines.append("- For any confirmed vulnerability, follow the target program's")
    lines.append("  disclosure policy and reporting format.")
    lines.append("- Do not attempt further exploitation beyond what the program's")
    lines.append("  rules of engagement allow.")
    lines.append("")

    report_path = os.path.join(outdir, "report.md")
    with open(report_path, "w") as f:
        f.write("\n".join(lines))

    print(f"Report written to {report_path}")


if __name__ == "__main__":
    main()