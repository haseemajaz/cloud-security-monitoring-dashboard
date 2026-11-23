# Architecture — Cloud Security Monitoring Dashboard

## Flow

```
data/sample_config.json  →  cloud_dashboard.py: check()  →  findings list
                                                      →  score()  →  0–100
                                                      →  html_report()  →  report.html
```

## Components

| Piece | Role |
|---|---|
| `data/sample_config.json` | Fictional account inventory: buckets, databases, IAM users, security groups |
| `RULES` in `cloud_dashboard.py` | The ruleset: id, severity, title, remediation. Add a rule by adding one tuple and one check. |
| `check()` | Pure function, inventory in, findings out. Easy to unit-test. |
| `score()` | 100 minus severity weights (Critical 25, High 15, Medium 5, Low 1), floored at 0. |
| `html_report()` | Self-contained HTML, no JavaScript, no external assets. |

## Design decisions

- **No cloud SDK, no credentials.** A portfolio demo that needs a real AWS account is a barrier; a rules engine over a JSON inventory shows the same thinking.
- **Standard library only.** `python3 cloud_dashboard.py` works on any machine with Python 3.10+.
- **Findings carry remediation.** A finding without a fix is a list; a finding with a fix is a security report.

## How to extend (for the README / interview)

1. Add a rule: a `RULES` tuple plus a check in `check()`.
2. Add a real data source: replace the JSON loader with a provider SDK call, behind an `--input` flag, keeping `check()` unchanged.
3. Add history: store each run's score in a JSONL file and chart it over time.
4. Add tests: `check()` is pure, so `assert check({...}) == [...]` is a one-line test.
