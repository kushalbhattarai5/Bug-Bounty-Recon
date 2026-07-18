#!/usr/bin/env python3
"""
notify_webhook.py — sends a webhook notification (Slack/Discord/generic)
for nuclei/takeover findings at or above a severity threshold, so you don't
have to check the terminal or report.md to know something important showed up.

Usage:
    python3 notify_webhook.py <recon_output_dir> <webhook_url> [--min-severity high] [--format slack|discord|generic]

Example:
    python3 notify_webhook.py results/example.com_20260101 https://hooks.slack.com/services/XXX --min-severity high
"""
import argparse
import json
import os
import sys
import urllib.request

SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def read_json_array(path):
    if not os.path.exists(path):
        return []
    try:
        with open(path, "r", errors="ignore") as f:
            content = f.read().strip()
        return json.loads(content) if content else []
    except json.JSONDecodeError:
        return []


def build_message(findings, target_dir):
    lines = [f"*New findings in* `{target_dir}`", ""]
    for f in findings:
        sev = f.get("info", {}).get("severity", "unknown")
        name = f.get("info", {}).get("name", f.get("template-id", "unknown"))
        host = f.get("host", "")
        lines.append(f"[{sev.upper()}] {name} — {host}")
    return "\n".join(lines)


def send(webhook_url, text, fmt):
    if fmt == "slack":
        payload = {"text": text}
    elif fmt == "discord":
        payload = {"content": text[:1900]}  # discord message length limit
    else:
        payload = {"message": text}

    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        webhook_url, data=data, headers={"Content-Type": "application/json"}
    )
    with urllib.request.urlopen(req, timeout=10) as resp:
        return resp.status


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("recon_dir")
    parser.add_argument("webhook_url")
    parser.add_argument("--min-severity", default="high", choices=list(SEVERITY_RANK.keys()))
    parser.add_argument("--format", default="slack", choices=["slack", "discord", "generic"])
    args = parser.parse_args()

    threshold = SEVERITY_RANK[args.min_severity]

    findings = read_json_array(os.path.join(args.recon_dir, "nuclei_results.json"))
    findings += read_json_array(os.path.join(args.recon_dir, "takeover_results.json"))

    to_send = [
        f for f in findings
        if SEVERITY_RANK.get(f.get("info", {}).get("severity", "info"), 0) >= threshold
    ]

    if not to_send:
        print(f"No findings at or above '{args.min_severity}'. Nothing sent.")
        return

    text = build_message(to_send, args.recon_dir)
    try:
        status = send(args.webhook_url, text, args.format)
        print(f"Sent {len(to_send)} finding(s) to webhook. HTTP {status}")
    except Exception as e:
        print(f"[!] Failed to send webhook: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
