# CTI Radar Dashboard

Public-source CTI dashboard for SOC analysts. Static web UI (Arabic + English terminology), Python collectors, scheduled GitHub Actions, GitHub Pages. **No Telegram bot is required.**

Setup and caveats: **[README_AR.md](README_AR.md)**.

## Local validation

```bash
python -m pip install -r requirements.txt
python -m unittest discover -s tests -v
python collect.py --check
python -m http.server 8000 -d site
```

Production source refresh: `.github/workflows/cti-dashboard.yml` scheduled hourly. Never commit secrets or internal customer information. Public website; browser notifications only while open.
