# 🛡️ SecretScanner

> A privacy-first, GUI-based secrets & credential leak detection platform.

---

## 🚀 Features

- **Privacy-First Core Engine**: Uses Shannon entropy calculations (0–8 bits) and multi-pattern regex matching to detect leaked API keys, AWS credentials, private keys, database connection strings, and tokens without storing raw secret values.
- **Modern Web Dashboard**: Served directly via FastAPI with interactive dark-mode glassmorphic interface, summary cards, and JSON/CSV data export.
- **Git History & Pre-Commit Guard**: Scan entire Git repository history across all commits or install an automated `.git/hooks/pre-commit` guard.
- **Ignore Rules Support**: Skips binary files, build artifacts (`node_modules`, `.venv`), and custom rules defined in `.secretscannerignore`.
- **HTML & Markdown Audit Reports**: Generate audit reports ready for compliance and security reviews.

---

## 🛠️ Quick Start

### 1. Setup Environment
```powershell
.\setup_project.ps1
```

### 2. Start Web GUI & REST API
```powershell
python -m uvicorn secret_scanner.api:app --host 127.0.0.1 --port 8000
```
Open **[http://127.0.0.1:8000](http://127.0.0.1:8000)** in your browser for the Web Dashboard or **[http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)** for API docs.

---

## 💻 CLI Usage

```powershell
# Scan current directory
python -m secret_scanner.core.scanner .

# Scan with JSON output
python -m secret_scanner.core.scanner . --json

# Generate HTML & Markdown security audit reports
python -m secret_scanner.core.scanner . --html audit_report.html --markdown audit_report.md

# Install Git Pre-Commit Hook
python -m secret_scanner.core.scanner --install-hook
```

---

## 🧪 Run Unit Tests

```powershell
python -m unittest discover tests
```

---

## 📂 Project Structure

```
Project/
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
    ├── __main__.py
    ├── git_scanner.py
    ├── core/
    │   ├── __init__.py
    │   ├── detectors.py
    │   ├── engine.py
    │   ├── hook.py
    │   ├── ignore.py
    │   ├── reporter.py
    │   ├── rules.py
    │   └── scanner.py
    └── api/
        ├── __init__.py
        └── app.py
```
