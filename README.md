# 🛡️ SecretScanner

> A privacy-first, GUI-based secrets & credential leak detection platform.

[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue)](https://www.python.org/downloads/)
[![GitHub stars](https://img.shields.io/github/stars/xorudra/secret-scanner?style=flat)](https://github.com/xorudra/secret-scanner/stargazers)
[![GitHub issues](https://img.shields.io/github/issues/xorudra/secret-scanner)](https://github.com/xorudra/secret-scanner/issues)


## 📑 Table of Contents
- [Features](#-features)
- [Quick Start](#-quick-start)
- [Running the Dashboard](#-running-the-dashboard)
- [How Scanning Works](#-how-scanning-works)
- [Configuration](#-configuration)
- [Reporting & Export](#-reporting--export)
- [Pre‑commit Hook (optional)](#-pre‑commit-hook-optional)
- [Contributing](#-contributing)
- [License](#-license)

---

## 🚀 Features

- **Privacy-First Core Engine**: Uses Shannon entropy calculations (0–8 bits) and multi-pattern regex matching to detect leaked API keys, AWS credentials, private keys, database connection strings, and tokens without storing raw secret values.
- **Modern Web Dashboard**: Served directly via FastAPI with an interactive dark-mode glassmorphic interface, summary cards, and JSON/CSV data export.
- **Git History Scanner**: Scan your entire Git repository history across all commits from the dashboard.
- **Ignore Rules Support**: Skips binary files, build artifacts (`node_modules`, `.venv`), and custom rules defined in `.secretscannerignore`.
- **HTML & Markdown Audit Reports**: Generate audit reports ready for compliance and security reviews — downloadable directly from the UI.

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
- Starts the server at **http://127.0.0.1:8000**
- Opens the dashboard in your default browser

> Browse to **[http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)** for the interactive REST API documentation.

---

## 🖥️ Using the Dashboard

Once the server is running, the dashboard lets you:

| Feature | How |
|---------|-----|
| **Scan a folder** | Enter a directory path → click **Scan Path** |
| **Scan text/snippet** | Paste code into the text area → click **Scan Text** |
| **Scan Git history** | Enter a repo path → click **Scan Git History** |
| **Export results** | Click **Download JSON** or **Download CSV** after a scan |
| **Generate reports** | Click **HTML Report** or **Markdown Report** to download audit files |

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
        └── app.py         ← FastAPI web app & REST endpoints
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

### 5️⃣ “Reporting & Export” – what formats are available

markdown
## 📊 Reporting & Export

After a scan finishes you can download the results in any of the following formats:

| Format | When to use it |
|--------|----------------|
| **HTML** | Human‑readable audit that you can share with auditors or embed in internal wikis. |
| **Markdown** | Quick copy‑paste into Confluence, GitHub READMEs, or security tickets. |
| **SARIF** | GitHub Security Alerts / code‑scanning integrations (`.sarif` file). |
| **JSON** | CI pipelines – pipe the JSON directly to other tools or to a “fail‑on‑findings” step. |

All reports contain the same fields shown in the dashboard (file, line, rule, severity, risk score, masked value, and optional Git metadata).  


### 7️⃣ “Contributing” – short guide

markdown
## 🤝 Contributing

Contributions are welcome! Here’s how to get started:

1. **Fork** the repo and clone your fork.  
2. Run `.\setup_project.ps1` to create the virtual environment.  
3. Make your changes (e.g., add a new detection rule or improve the UI).  
4. Run the test suite to ensure everything passes:  

   ```powershell
   python -m unittest discover tests
```

### 8️⃣ “License” – keep the standard MIT notice (if you haven’t added it yet)

```markdown
## 📄 License
```
This project is licensed under the **MIT License** – see the `LICENSE` file for details.
