# SentrySAST — Semgrep + AST + Entropy, With Claude Writing the Fix

> **A SOC-grade static analysis tool for Python: Semgrep rules + AST traversal + Shannon-entropy secret scanning, with every finding enriched by a plain-English Claude explanation and a concrete remediation snippet. Ships as CLI, REST API, and a React dashboard. Exports SARIF 2.1 for GitHub Code Scanning.**

<p align="center"><img src="assets/hero.gif" alt="SentrySAST — SAST + Claude in the loop" width="720"></p>

<p align="center">
  <img src="https://img.shields.io/github/actions/workflow/status/Danush-Aries/sast-scanner/ci.yml?branch=main&style=flat-square" alt="build">
  <img src="https://img.shields.io/badge/license-MIT-00ff41?style=flat-square" alt="license">
  <img src="https://img.shields.io/badge/made%20with-Python%203.9%2B-3776AB?style=flat-square&logo=python&logoColor=white" alt="python">
  <img src="https://img.shields.io/badge/SARIF-2.1-blueviolet?style=flat-square" alt="sarif">
  <img src="https://img.shields.io/badge/Claude-Haiku%204.5-D97757?style=flat-square&logo=anthropic&logoColor=white" alt="claude">
</p>

## Why this exists

Semgrep flags a `subprocess.call(user_input, shell=True)` — great, but the next dev on the ticket still has to open a browser, read OWASP, and figure out whether that line is exploitable in this codebase. SentrySAST closes that gap: after the three parallel scanners (Semgrep rules + `ast` traversal + Shannon-entropy secret detection) run, every finding is piped through `claude-haiku-4-5` with prompt caching, which returns a Critical/High/Medium/Low risk label, a plain-English explanation, and a concrete fix. Output is SARIF 2.1 so GitHub Advanced Security, VS Code SARIF Viewer, and every SIEM dashboard already know how to read it.

## Try it in 60 seconds

```bash
git clone https://github.com/Danush-Aries/sast-scanner.git
cd sast-scanner
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

cp .env.example .env               # add ANTHROPIC_API_KEY (or set DISABLE_AI_EXPLAINER=true)
python sast_scanner.py scan /path/to/project --output results.sarif
```

No API key? `DISABLE_AI_EXPLAINER=true python sast_scanner.py scan .` runs fully offline.
REST API: `uvicorn web.backend.main:app --reload --port 8003`.
Dashboard: `cd web/frontend && npm install && npm run dev` (proxies to :8003).

## How it works

- **Three parallel scanners** — `scanner/engine.py` fans out to (a) Semgrep with rules in `rules/*.yaml`, (b) `scanner/ast_analyzer.py` walking the AST for `execute()` / `os.system` / `subprocess.*` with tainted args, and (c) `scanner/secret_detector.py` combining regex (AWS keys, GitHub tokens, JWT) with Shannon entropy for unknown-shape secrets.
- **AI explainer with prompt caching** — `scanner/ai_explainer.py` flags the system prompt `cache_control: ephemeral` so repeated scans of the same repo cost cents instead of dollars.
- **SARIF 2.1 export (`scanner/sarif_exporter.py`)** — the industry-standard machine-readable format that plugs straight into GitHub Code Scanning, VS Code SARIF Viewer, and enterprise SIEMs.
- **Adversarial bypass tests (`adversarial_tests.py`)** — a growing suite of obfuscation attempts (base64-encoded shell, string-concat SQL, secrets split across lines) used as a regression harness.
- **Web dashboard** — React + TypeScript + Vite; severity charts (Recharts), per-finding drill-down, filter by rule ID.

## Screenshots

| CLI scan | SARIF report in GitHub | React dashboard |
|---|---|---|
| ![](assets/screenshot-1.png) | ![](assets/screenshot-2.png) | ![](assets/screenshot-3.png) |

## Detection categories

| Category | Detection Method |
|---|---|
| SQL Injection | Semgrep rules + AST analysis of `execute()` / `executemany()` calls |
| Command Injection | Semgrep rules + AST analysis of `os.system`, `subprocess.*` calls |
| Leaked Secrets | Regex pattern matching (AWS keys, GitHub tokens, etc.) + Shannon entropy analysis |

## Usage

### CLI scan

```bash
python sast_scanner.py scan /path/to/your/python/project
python sast_scanner.py scan /path/to/project --output results.sarif
python sast_scanner.py scan /path/to/project --rules ./rules --output results.sarif
DISABLE_AI_EXPLAINER=true python sast_scanner.py scan /path/to/project
```

Example output:

```
                        Security Findings
┌─────────────────────┬──────────────────┬──────┬───────────────────────────────────────┬──────────┐
│ ID                  │ File             │ Line │ Message                               │ Risk     │
├─────────────────────┼──────────────────┼──────┼───────────────────────────────────────┼──────────┤
│ command_injection   │ app/tasks.py     │  42  │ Potential Command Injection: dynamic… │ High     │
│ sql_injection       │ app/models.py    │  87  │ Potential SQL Injection: dynamic …    │ Critical │
│ secret_detected     │ config/dev.py    │   5  │ Potential Generic API Key detected    │ High     │
└─────────────────────┴──────────────────┴──────┴───────────────────────────────────────┴──────────┘
```

### REST API

```bash
uvicorn web.backend.main:app --reload --port 8003

curl -X POST http://localhost:8003/scan \
  -H "Content-Type: application/json" \
  -d '{"target_path": "/absolute/path/to/project", "rules_path": "/absolute/path/to/rules"}'
```

### Tests

```bash
DISABLE_AI_EXPLAINER=true pytest tests/ -v
DISABLE_AI_EXPLAINER=true python adversarial_tests.py
```

## Environment variables

| Variable | Required | Default | Description |
|---|---|---|---|
| `ANTHROPIC_API_KEY` | Yes (unless AI disabled) | — | Your Anthropic API key |
| `DISABLE_AI_EXPLAINER` | No | `false` | Set to `true` to skip AI calls entirely |

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
│   ├── cmd_injection.yaml
│   ├── sqli.yaml
│   └── secrets.yaml
├── tests/
├── web/
│   ├── backend/main.py        # FastAPI REST API
│   └── frontend/              # React + TypeScript + Vite dashboard
├── adversarial_tests.py       # Bypass-attempt test suite
├── requirements.txt
└── .github/workflows/ci.yml
```

## Stack

Semgrep · Python `ast` · Shannon entropy + regex · Anthropic `claude-haiku-4-5` (prompt cached) · `sarif-om` · Rich (CLI) · FastAPI + Uvicorn · React 18 + TypeScript + Vite + Tailwind + Recharts · GitHub Actions CI.

## Contributing

PRs welcome. New rules are just YAML in `rules/`; Semgrep picks them up on next scan. New Python vulnerability classes go in `scanner/ast_analyzer.py` — implement a `_check_<name>(node)` visitor and register it. Adversarial test cases go in `adversarial_tests.py` as short strings + expected finding IDs.

## License

[MIT](https://opensource.org/licenses/MIT).

---

### More from Danush

- [ponytail-for-python](https://github.com/Danush-Aries/ponytail-for-python) — code intelligence for Python codebases
- [Agentic_Systems](https://github.com/Danush-Aries/Agentic_Systems) — reference implementations of agent patterns
- [autonomous-coding-agent](https://github.com/Danush-Aries/autonomous-coding-agent) — full-auto engineering agent
- [computer-use-agent](https://github.com/Danush-Aries/computer-use-agent) — Claude drives your desktop via VNC
- [browser-automation-agent](https://github.com/Danush-Aries/browser-automation-agent) — Claude drives Playwright
- [blinkchat](https://github.com/Danush-Aries/blinkchat) — realtime chat with vibes
