# SentrySAST

![Python](https://img.shields.io/badge/Python-3.9%2B-blue?logo=python&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green)
![CI](https://img.shields.io/badge/CI-GitHub%20Actions-black?logo=githubactions)
![AI Powered](https://img.shields.io/badge/AI-Claude%20Haiku-orange?logo=anthropic)

A SOC-grade **Static Application Security Testing (SAST)** tool for Python codebases.
SentrySAST combines Semgrep rule-based scanning, AST analysis, and high-entropy string detection with AI-powered vulnerability explanations via the [Anthropic Claude API](https://www.anthropic.com/), producing industry-standard SARIF reports.

---

## What it does

SentrySAST scans Python source code for three categories of security issues:

| Category | Detection Method |
|---|---|
| SQL Injection | Semgrep rules + AST analysis of `execute()` / `executemany()` calls |
| Command Injection | Semgrep rules + AST analysis of `os.system`, `subprocess.*` calls |
| Leaked Secrets | Regex pattern matching (AWS keys, GitHub tokens, etc.) + Shannon entropy analysis |

Each finding is automatically enriched by Claude, which provides a plain-English explanation, a risk level (Critical / High / Medium / Low), and concrete remediation advice.

Results are exported as [SARIF 2.1](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html), compatible with GitHub Code Scanning, VS Code SARIF Viewer, and most enterprise security dashboards.

---

## Features

- **Multi-layer detection** — Semgrep rules, AST traversal, and entropy analysis work in parallel
- **AI explanations** — Claude `claude-haiku-4-5` explains each finding in plain English with a remediation snippet; uses prompt caching to minimise API cost
- **SARIF export** — machine-readable output that plugs into GitHub Advanced Security and SIEM tools
- **Rich CLI** — colour-coded terminal output powered by `rich`
- **REST API** — FastAPI backend lets you integrate scanning into CI pipelines or IDEs
- **Web dashboard** — React/TypeScript SPA with severity charts and a finding detail view
- **Graceful AI-off mode** — set `DISABLE_AI_EXPLAINER=true` to run fully offline with no API key

---

## Installation

```bash
# 1. Clone the repository
git clone https://github.com/dhanush-org/sast-scanner.git
cd sast-scanner

# 2. Create and activate a virtual environment (recommended)
python -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate

# 3. Install Python dependencies
pip install -r requirements.txt

# 4. Copy the example environment file and add your API key
cp .env.example .env
# Edit .env and set ANTHROPIC_API_KEY=<your key>
```

> **Semgrep** is required for rule-based scanning. It is installed automatically via `requirements.txt`.

---

## Usage

### CLI scan

```bash
# Scan a directory and print a rich table of findings
python sast_scanner.py scan /path/to/your/python/project

# Save results as SARIF
python sast_scanner.py scan /path/to/project --output results.sarif

# Use a custom rules directory
python sast_scanner.py scan /path/to/project --rules ./rules --output results.sarif

# Disable AI explanations (no API key needed)
DISABLE_AI_EXPLAINER=true python sast_scanner.py scan /path/to/project
```

Example output:

```
Scanning /path/to/project using rules from /home/user/sast-scanner/rules...

                        Security Findings
┌─────────────────────┬──────────────────┬──────┬───────────────────────────────────────┬──────────┐
│ ID                  │ File             │ Line │ Message                               │ Risk     │
├─────────────────────┼──────────────────┼──────┼───────────────────────────────────────┼──────────┤
│ command_injection   │ app/tasks.py     │  42  │ Potential Command Injection: dynamic… │ High     │
│ sql_injection       │ app/models.py    │  87  │ Potential SQL Injection: dynamic …    │ Critical │
│ secret_detected     │ config/dev.py    │   5  │ Potential Generic API Key detected    │ High     │
└─────────────────────┴──────────────────┴──────┴───────────────────────────────────────┴──────────┘

SARIF report saved to results.sarif
```

### REST API

```bash
# Start the FastAPI backend
uvicorn web.backend.main:app --reload --port 8003
```

```bash
# Trigger a scan via HTTP
curl -X POST http://localhost:8003/scan \
  -H "Content-Type: application/json" \
  -d '{"target_path": "/absolute/path/to/project", "rules_path": "/absolute/path/to/rules"}'
```

### Web dashboard

```bash
# Install frontend dependencies (first time only)
cd web/frontend
npm install

# Start the dev server (proxies API calls to localhost:8003)
npm run dev
```

Open [http://localhost:5173](http://localhost:5173) in your browser.

### Adversarial tests

```bash
DISABLE_AI_EXPLAINER=true python adversarial_tests.py
```

### Unit tests

```bash
DISABLE_AI_EXPLAINER=true pytest tests/ -v
```

---

## Project structure

```
sast-scanner/
├── sast_scanner.py            # CLI entry point
├── scanner/
│   ├── engine.py              # Orchestrates all scan phases
│   ├── cli.py                 # Argument parsing + rich output
│   ├── ast_analyzer.py        # Python AST-based vulnerability detection
│   ├── secret_detector.py     # Regex + Shannon entropy secret detection
│   ├── ai_explainer.py        # Claude API integration (with prompt caching)
│   └── sarif_exporter.py      # SARIF 2.1 report generation
├── rules/
│   ├── cmd_injection.yaml     # Semgrep rules for command injection
│   ├── sqli.yaml              # Semgrep rules for SQL injection
│   └── secrets.yaml           # Semgrep rules for hardcoded secrets
├── tests/
│   ├── test_ast_analyzer.py   # Unit tests for AST analysis
│   └── test_secret_detector.py # Unit tests for secret detection + engine
├── web/
│   ├── backend/main.py        # FastAPI REST API
│   └── frontend/              # React + TypeScript + Vite dashboard
│       ├── index.html
│       ├── vite.config.ts
│       └── src/App.tsx
├── adversarial_tests.py       # Bypass-attempt test suite
├── .env.example               # Environment variable template
├── requirements.txt           # Python dependencies
└── .github/workflows/ci.yml  # GitHub Actions CI
```

---

## Tech stack

| Layer | Technology |
|---|---|
| Static analysis rules | [Semgrep](https://semgrep.dev/) |
| AST analysis | Python `ast` standard library |
| Secret detection | Shannon entropy + regex |
| AI explanations | [Anthropic Claude](https://www.anthropic.com/) (`claude-haiku-4-5`) with prompt caching |
| Report format | [SARIF 2.1](https://docs.oasis-open.org/sarif/sarif/v2.1.0/) via `sarif-om` |
| CLI | [Rich](https://rich.readthedocs.io/) |
| REST API | [FastAPI](https://fastapi.tiangolo.com/) + [Uvicorn](https://www.uvicorn.org/) |
| Frontend | React 18, TypeScript, Vite, Tailwind CSS, Recharts |

---

## Environment variables

| Variable | Required | Default | Description |
|---|---|---|---|
| `ANTHROPIC_API_KEY` | Yes (unless AI disabled) | — | Your Anthropic API key |
| `DISABLE_AI_EXPLAINER` | No | `false` | Set to `true` to skip AI calls entirely |

---

## License

[MIT](https://opensource.org/licenses/MIT)
