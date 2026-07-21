#!/usr/bin/env python3
"""
js_secret_scan.py — scans downloaded JS files for likely secrets/tokens and
interesting endpoint paths using regex patterns. This is pattern matching
only (like grep) — every hit is a LEAD to manually verify, not a confirmed
leak. High false-positive rate is expected and normal for this kind of scan.

Usage:
    python3 js_secret_scan.py <js_files_dir> <output_report.md> [known_hosts.txt]
"""
import os
import re
import sys

# (label, regex, notes)
PATTERNS = [
    ("AWS Access Key ID", r"AKIA[0-9A-Z]{16}", "high"),
    ("AWS Secret Key (heuristic)", r"(?i)aws(.{0,20})?secret(.{0,20})?['\"][0-9a-zA-Z/+]{40}['\"]", "high"),
    ("Google API Key", r"AIza[0-9A-Za-z\-_]{35}", "high"),
    ("Slack Token", r"xox[baprs]-[0-9a-zA-Z-]{10,48}", "high"),
    ("Stripe Live Key", r"sk_live_[0-9a-zA-Z]{24,}", "high"),
    ("Generic Bearer/Auth Token", r"(?i)(authorization|bearer)['\"]?\s*[:=]\s*['\"][A-Za-z0-9\-_.]{20,}['\"]", "medium"),
    ("JWT", r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}", "medium"),
    ("Private Key Block", r"-----BEGIN (RSA |EC |)PRIVATE KEY-----", "high"),
    ("Generic API Key Assignment", r"(?i)(api[_-]?key|apikey|secret[_-]?key)['\"]?\s*[:=]\s*['\"][0-9a-zA-Z\-_]{16,}['\"]", "medium"),
    ("Firebase DB URL", r"https://[a-z0-9-]+\.firebaseio\.com", "low"),
    ("Internal/absolute API path", r"['\"](/api/[a-zA-Z0-9/_\-{}.]{3,})['\"]", "low"),
    ("Internal hostname reference", r"(?i)https?://[a-z0-9.-]*\.(internal|corp|local|staging|dev)[a-z0-9.-]*", "low"),
]


def scan_file(path):
    findings = []
    try:
        with open(path, "r", errors="ignore") as f:
            content = f.read()
    except Exception:
        return findings

    for label, pattern, severity in PATTERNS:
        for m in re.finditer(pattern, content):
            snippet = m.group(0)
            if len(snippet) > 120:
                snippet = snippet[:117] + "..."
            findings.append((severity, label, snippet))
    return findings


def main():
    if len(sys.argv) < 3:
        print("Usage: js_secret_scan.py <js_files_dir> <output.md> [known_hosts.txt]")
        sys.exit(1)

    js_dir = sys.argv[1]
    out_path = sys.argv[2]

    all_findings = {}  # filename -> list of (severity, label, snippet)
    if os.path.isdir(js_dir):
        for fname in sorted(os.listdir(js_dir)):
            fpath = os.path.join(js_dir, fname)
            if not os.path.isfile(fpath):
                continue
            findings = scan_file(fpath)
            if findings:
                all_findings[fname] = findings

    sev_rank = {"high": 0, "medium": 1, "low": 2}
    total = sum(len(v) for v in all_findings.values())

    lines = []
    lines.append("# JS secret/endpoint scan")
    lines.append("")
    lines.append(f"Files scanned: {len(os.listdir(js_dir)) if os.path.isdir(js_dir) else 0}")
    lines.append(f"Files with matches: {len(all_findings)}")
    lines.append(f"Total pattern matches: {total}")
    lines.append("")
    lines.append("> Every match below is a regex hit, not a confirmed secret.")
    lines.append("> False positives are common (test/dummy keys, unrelated strings")
    lines.append("> that happen to match the pattern shape, etc). Manually verify")
    lines.append("> each one before treating it as a real finding.")
    lines.append("")

    if not all_findings:
        lines.append("No matches found.")
    else:
        for fname, findings in all_findings.items():
            findings.sort(key=lambda x: sev_rank.get(x[0], 3))
            lines.append(f"## {fname}")
            lines.append("")
            lines.append("| Severity | Type | Match |")
            lines.append("|---|---|---|")
            for severity, label, snippet in findings:
                snippet = snippet.replace("|", "\\|").replace("\n", " ")
                lines.append(f"| {severity} | {label} | `{snippet}` |")
            lines.append("")

    with open(out_path, "w") as f:
        f.write("\n".join(lines))

    print(f"Report written to {out_path} ({total} matches across {len(all_findings)} files)")


if __name__ == "__main__":
    main()
