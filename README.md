# 🛡️ SecretScanner

> A privacy-first, GUI-based secrets & credential leak detection platform.

---

## 🚀 Features

- **Privacy-First Core Engine**: Uses Shannon entropy calculations (0–8 bits) and multi-pattern regex matching to detect leaked API keys, AWS credentials, private keys, database connection strings, and tokens without storing raw secret values.
- **Modern Web Dashboard**: Served directly via FastAPI with an interactive dark-mode glassmorphic interface, summary cards, and JSON/CSV data export.
- **Git History Scanner**: Scan your entire Git repository history across all commits from the dashboard.
- **Ignore Rules Support**: Skips binary files, build artifacts (`node_modules`, `.venv`), and custom rules defined in `.secretscannerignore`.
- **HTML & Markdown Audit Reports**: Generate audit reports ready for compliance and security reviews — downloadable directly from the UI.

---

## 🛠️ Quick Start

### 1. Change your Default PowerShell Directory to "secret_scanner" Folder Directory (Example) :

```powershell
cd "C:\Users\<YourName>\Downloads\secret-scanner"
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
