# 08 — Cloud Security Monitoring Dashboard

**Area:** Security Engineering · **Stack:** Python 3.10+ (standard library only) · **Status:** Portfolio starter, safe local demo

## What it does

Reads a cloud inventory file (demo data in `data/sample_config.json`, in the shape of an AWS-style account inventory) and checks it against a small, documented ruleset:

- Storage buckets open to the public
- Databases exposed to `0.0.0.0/0`
- Unencrypted storage / databases
- IAM users with no MFA
- CloudTrail / audit logging disabled
- Security groups allowing SSH / RDP from anywhere

It scores the account, lists findings by severity, and generates a self-contained HTML dashboard (`report.html`) you can open in a browser. No cloud credentials are needed, and nothing is sent anywhere. All data is local demo data.

## What an employer sees

- A rules engine with severity, remediation text, and a CIS-style control reference per finding
- A readable HTML report, not just terminal output
- A clear separation between data (`data/`), rules (`cloud_dashboard.py`), and output (`report.html`)

## How to run

```bash
cd 08-cloud-security-monitoring-dashboard
python3 cloud_dashboard.py
# writes report.html and prints a summary

python3 cloud_dashboard.py --input data/sample_config.json --output report.html
python3 cloud_dashboard.py --input data/sample_config.json --format json
```

Open `report.html` in a browser to see the dashboard.

## Try it yourself

Edit `data/sample_config.json`: set a bucket to `"public": false`, give a user `"mfa": true`, or turn logging on, re-run, and watch the score and findings change. That is the whole point of the demo.

## Safety

Educational only. This tool never connects to a real cloud account, never needs credentials, and must not be pointed at real infrastructure without going through the provider's own console / audit tools. The sample data is fictional.
