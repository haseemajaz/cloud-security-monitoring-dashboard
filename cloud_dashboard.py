#!/usr/bin/env python3
"""Cloud Security Monitoring Dashboard — safe local demo.

Reads a JSON inventory (demo data only), checks it against a small
ruleset, prints a summary, and writes a self-contained HTML report.
Standard library only. No credentials, no network, no real cloud.
"""
import argparse
import json
import sys
from pathlib import Path

RULES = [
    ("CLOUD-01", "High", "Public storage bucket",
     "Bucket is publicly readable. Make it private and use signed URLs."),
    ("CLOUD-02", "Critical", "Database exposed to 0.0.0.0/0",
     "Database is reachable from the internet. Restrict to a private subnet."),
    ("CLOUD-03", "Medium", "Unencrypted storage",
     "Storage is not encrypted at rest. Enable encryption."),
    ("CLOUD-04", "High", "IAM user without MFA",
     "User has no multi-factor authentication. Require MFA."),
    ("CLOUD-05", "Medium", "Audit logging disabled",
     "CloudTrail / audit logging is off. Enable it and alert on changes."),
    ("CLOUD-06", "High", "SSH/RDP open to the world",
     "Security group allows SSH or RDP from 0.0.0.0/0. Restrict to a bastion/VPN."),
]

SEVERITY_WEIGHT = {"Critical": 25, "High": 15, "Medium": 5, "Low": 1}


def check(inventory):
    findings = []
    for bucket in inventory.get("buckets", []):
        if bucket.get("public"):
            findings.append(("CLOUD-01", bucket["name"]))
        if not bucket.get("encrypted", True):
            findings.append(("CLOUD-03", bucket["name"]))
    for db in inventory.get("databases", []):
        if "0.0.0.0/0" in db.get("allowed_cidrs", []):
            findings.append(("CLOUD-02", db["name"]))
        if not db.get("encrypted", True):
            findings.append(("CLOUD-03", db["name"]))
    for user in inventory.get("iam_users", []):
        if not user.get("mfa", False):
            findings.append(("CLOUD-04", user["name"]))
    if not inventory.get("audit_logging", False):
        findings.append(("CLOUD-05", "account"))
    for sg in inventory.get("security_groups", []):
        for rule in sg.get("ingress", []):
            if rule.get("cidr") == "0.0.0.0/0" and rule.get("port") in (22, 3389):
                findings.append(("CLOUD-06", sg["name"]))
    rule_by_id = {r[0]: r for r in RULES}
    return [
        {"id": rid, "severity": rule_by_id[rid][1], "title": rule_by_id[rid][2],
         "remediation": rule_by_id[rid][3], "resource": resource}
        for rid, resource in findings
    ]


def score(findings):
    return max(0, 100 - sum(SEVERITY_WEIGHT[f["severity"]] for f in findings))


def html_report(inventory, findings, total):
    rows = "".join(
        f"<tr><td>{f['id']}</td><td>{f['severity']}</td><td>{f['title']}</td>"
        f"<td>{f['resource']}</td><td>{f['remediation']}</td></tr>"
        for f in findings
    ) or "<tr><td colspan='5'>No findings. Demo account is clean.</td></tr>"
    return f"""<!DOCTYPE html><html><head><meta charset='utf-8'>
<title>Cloud Security Dashboard — {inventory.get('account', 'demo')}</title>
<style>body{{font-family:sans-serif;max-width:900px;margin:2rem auto;padding:0 1rem}}
table{{border-collapse:collapse;width:100%}}td,th{{border:1px solid #ccc;padding:6px;text-align:left}}
h1{{font-size:1.5rem}}</style></head><body>
<h1>Cloud Security Monitoring Dashboard</h1>
<p>Account: {inventory.get('account', 'demo')} · Score: <strong>{total}/100</strong> ·
Findings: {len(findings)}</p>
<table><tr><th>ID</th><th>Severity</th><th>Finding</th><th>Resource</th><th>Remediation</th></tr>
{rows}</table><p>Demo data only. No real cloud account was accessed.</p>
</body></html>"""


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", default="data/sample_config.json")
    parser.add_argument("--output", default="report.html")
    parser.add_argument("--format", choices=["text", "json"], default="text")
    args = parser.parse_args()
    inventory = json.loads(Path(args.input).read_text())
    findings = check(inventory)
    total = score(findings)
    if args.format == "json":
        print(json.dumps({"account": inventory.get("account"), "score": total,
                          "findings": findings}, indent=2))
    else:
        print(f"Account: {inventory.get('account')}  Score: {total}/100  "
              f"Findings: {len(findings)}")
        for f in findings:
            print(f"  [{f['severity']}] {f['id']} {f['title']} — {f['resource']}")
    Path(args.output).write_text(html_report(inventory, findings, total))
    print(f"Report written to {args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
