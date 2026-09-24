# 🛡️ SecretScanner

> A privacy-first, GUI-based secrets & credential leak detection platform.

[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue)](https://www.python.org/downloads/)
[![GitHub stars](https://img.shields.io/github/stars/xorudra/secret-scanner?style=flat)](https://github.com/xorudra/secret-scanner/stargazers)
[![GitHub issues](https://img.shields.io/github/issues/xorudra/secret-scanner)](https://github.com/xorudra/secret-scanner/issues)


## 📑 Table of Contents
- [Features](https://github.com/xorudra/secret-scanner#-features)
- [How Scanning Works](https://github.com/xorudra/secret-scanner#-how-scanning-works)
- [Configuration](https://github.com/xorudra/secret-scanner#%EF%B8%8F-configuration)
- [Quick Start](https://github.com/xorudra/secret-scanner#%EF%B8%8F-quick-start)
- [Using the Dashboard](https://github.com/xorudra/secret-scanner#%EF%B8%8F-using-the-dashboard)
- [Project Structure](https://github.com/xorudra/secret-scanner#-project-structure)
- [Pre‑commit Hook (optional)](https://github.com/xorudra/secret-scanner#-precommit-hook-optional)
- [Reporting & Export](https://github.com/xorudra/secret-scanner#-reporting--export--what-formats-are-available)
- [Contributing](https://github.com/xorudra/secret-scanner#-contributing--short-guide)
- [License](https://github.com/xorudra/secret-scanner#-license--keep-the-standard-mit-notice-if-you-havent-added-it-yet)

---

## 🚀 Features

- **Privacy-First Core Engine**: Uses Shannon entropy calculations (0–8 bits) and multi-pattern regex matching to detect leaked API keys, AWS credentials, private keys, database connection strings, and tokens without storing raw secret values.
- **Modern Web Dashboard**: Served directly via FastAPI with an interactive dark-mode glassmorphic interface, summary cards, and JSON/CSV data export.
- **Git History Scanner**: Scan your entire Git repository history across all commits from the dashboard.
- **Scan History**: Every completed scan is saved (persisted in your browser) and can be restored into the Results view with one click.
- **Scheduled Scans**: Automate recurring scans with cron expressions (path, git, or URL scans) and get notified via webhooks signed with HMAC-SHA256.
- **Diff View (Scan Comparison)**: Compare any two scans from history to instantly see **new**, **resolved**, and **unchanged** findings using fingerprint-based matching.
- **Team Projects**: Group multiple repositories into projects, run a *Scan All* across every configured repository, and view per-project dashboards with aggregated stats.
- **Detection Rule Editor**: Browse all active rules and add your own regex rules directly from the dashboard (saved to `rules/default_rules.yaml`).
- **Ignore Rules Support**: Skips binary files, build artifacts (`node_modules`, `.venv`), and custom rules defined in `.secretscannerignore`.
- **HTML, Markdown, PDF & SARIF Audit Reports**: Generate audit reports ready for compliance and security reviews — downloadable directly from the UI.

## 🧩 How Scanning Works

SecretScanner’s engine combines **two complementary techniques**:

| Technique | What it does | Why it helps |
|-----------|--------------|--------------|
| **Shannon entropy** | Calculates the information entropy of every alphanumeric token. Tokens with entropy ≥ 4.5 bits are considered “high‑entropy”. | Detects random‑looking strings even when they don’t match a known pattern. |
| **Regex rule‑set** | A curated list of regular expressions for known credential formats (AWS, Stripe, GitHub, Slack, etc.). | Quickly matches the exact shape of most production secrets. |

Both signals are merged into a **risk score (0‑1)**; only tokens above a configurable threshold appear in the UI. The engine runs **pure‑Python**, never writes the raw secret to disk, and can be called from the FastAPI endpoints or from the internal CLI used by the pre‑commit hook.  

## ⚙️ Configuration

| File | Purpose |
|------|----------|
| `.secretscannerignore` | List of glob patterns (one per line) for files/folders the scanner should skip – e.g., `node_modules/`, `*.png`, `tests/**`. |
| `rules/default_rules.yaml` | Built‑in detection rules (regex + entropy thresholds). |
| **Custom rule file** | You can supply your own YAML with the same schema and point the dashboard to it via the “Custom Rules” field or the `--rules <file>` CLI flag. |
| **Add Rule UI** | On the Detection Rules page, click **Add Rule** to append a new rule to `rules/default_rules.yaml` without editing YAML by hand. |

**Example `.secretscannerignore`**  

```text
# Skip binary assets and test fixtures
*.png
*.zip
tests/**
```

**Adding a custom rule** – copy rules/default_rules.yaml to my_rules.yaml, edit or add a new entry, then run:

```powershell
python -m secret_scanner --rules my_rules.yaml .
```

---

## 🛠️ Quick Start

### 1. Change your Default PowerShell Directory to "secret_scanner" Folder Directory (Example) :

```powershell
cd "C:\Users\<YourName>\Downloads\secret-scanner"
```

**Note**: If PowerShell prevents .\setup_project.ps1 from running, open PowerShell and run:

```powershell
Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned
```

### 2. Setup Environment
```powershell
.\setup_project.ps1
```

### 3. Launch the Web Dashboard
```powershell
python -m secret_scanner
```

This automatically:
- Starts the server at **http://127.0.0.1:8000** (if port 8000 is already taken by another app, the next free port is used and printed)
- Opens the dashboard in your default browser

Useful flags:

```powershell
python -m secret_scanner --port 8010     # always serve on a specific port
python -m secret_scanner --no-browser     # do not open a browser window
```

> If you run other web apps on port 8000, launch SecretScanner with an explicit
> port (e.g. `--port 8010`) and open that URL — otherwise the browser tab may
> talk to the wrong application and show 404s for endpoints it does not own.

> Browse to **[http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)** for the interactive REST API documentation.

---

## 🖥️ Using the Dashboard

The sidebar gives you access to every page:

| Page | What you can do |
|------|-----------------|
| **Directory / File** | Enter a directory or file path → click **Scan Path** (or drag & drop a file / folder) |
| **Text Snippet** | Paste code into the text area → click **Scan Text** |
| **Git History** | Enter a repo path → click **Scan Git History** (checks every commit) |
| **URL / Website** | Enter a URL → fetch and scan the response body |
| **Results** | Sortable, filterable, paginated findings table with risk scores, finding details, fingerprint copy, and false-positive dismissal |
| **Overview** | Aggregate stats, severity donut chart, and top affected files |
| **Scan History** | Every completed scan is listed (persisted across reloads) — click one to restore it into Results, or clear history |
| **Scheduled Scans** | Create cron-scheduled recurring scans (path / git / URL), attach optional HMAC-signed webhooks, run immediately, pause/resume, or delete |
| **Scan Comparison** | Pick a baseline and a current scan from history → see **New / Resolved / Unchanged** findings side by side |
| **Team Projects** | Create projects with multiple repositories (path, git, or URL targets), run **Scan All**, view a per-project dashboard, and delete projects |
| **Detection Rules** | View every active rule with its regex and severity, or click **Add Rule** to create a new detection rule from the UI |
| **Export results** | From Results: **Download JSON / CSV** |
| **Generate reports** | From Results: **HTML / Markdown / PDF / SARIF** audit reports |

---

## 🧪 Run Unit Tests

```powershell
python -m unittest discover tests
```

---

## 📂 Project Structure

```
secret-scanner/
├── pyproject.toml
├── setup_project.ps1
├── README.md
├── rules/
│   └── default_rules.yaml
├── tests/
│   ├── test_api.py
│   ├── test_engine.py
│   └── test_reporter.py
└── secret_scanner/
    ├── __init__.py
    ├── __main__.py        ← GUI launcher
    ├── git_scanner.py
    ├── core/
    │   ├── engine.py
    │   ├── reporter.py
    │   ├── rules.py
    │   └── scanner.py     ← Core scan engine (used by API)
    └── api/
        ├── __init__.py
        ├── app.py         ← FastAPI web app & REST endpoints
        ├── scheduler.py   ← Cron scheduling + webhook alerts (/schedule)
        ├── projects.py    ← Team Projects API (/projects)
        └── templates/
            └── index.html ← Dashboard UI (all pages)
```
## 🪝 Pre‑commit Hook (optional)

If you want to **prevent secrets from ever reaching your repo**, install the hook once:

```powershell
python -m secret_scanner --install-hook
```
This runs a one‑time setup and adds a **pre‑commit hook** that automatically scans any changes you `git add` before allowing the commit.  

To **uninstall** the hook later:

```powershell
python -m secret_scanner --uninstall-hook
```

### 📊 “Reporting & Export” – what formats are available

After a scan finishes you can download the results in any of the following formats:

| Format | When to use it |
|--------|----------------|
| **HTML** | Human‑readable audit that you can share with auditors or embed in internal wikis. |
| **Markdown** | Quick copy‑paste into Confluence, GitHub READMEs, or security tickets. |
| **SARIF** | GitHub Security Alerts / code‑scanning integrations (`.sarif` file). |
| **JSON** | CI pipelines – pipe the JSON directly to other tools or to a “fail‑on‑findings” step. |

All reports contain the same fields shown in the dashboard (file, line, rule, severity, risk score, masked value, and optional Git metadata).  


### 🤝 “Contributing” – short guide

Contributions are welcome! Here’s how to get started:

1. **Fork** the repo and clone your fork.  
2. Run `.\setup_project.ps1` to create the virtual environment.  
3. Make your changes (e.g., add a new detection rule or improve the UI).  
4. Run the test suite to ensure everything passes:  

```powershell
   python -m unittest discover tests
```

### 📄 “License” – keep the standard MIT notice (if you haven’t added it yet)

```markdown
## License
```
This project is licensed under the **MIT License** – see the `LICENSE` file for details.
