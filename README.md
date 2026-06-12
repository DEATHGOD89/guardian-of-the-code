# CodeSecureScan – Offline Local Code Security Scanner

**No AI, no network – just rules and regex.**

CodeSecureScan helps you find bugs, security flaws, and authentication issues in any source code repository. It works 100% offline and is fully under your control.

## Features

- Scans all programming languages (text‑based source files)
- Pre‑built rules for:
  - SQL injection, XSS, command injection
  - Hardcoded secrets, weak cryptography
  - Missing authentication checks
  - Dangerous functions (eval, exec, system)
  - Common bugs (null dereference, resource leaks)
- Add your own custom rules via YAML (keywords, regex, context)
- Output: colorized terminal + JSON / HTML reports
- Lightweight, no runtime dependencies on AI or cloud services

## Installation

Requires **Python 3.8+** and `pip`.

```bash
git clone https://github.com/your-username/CodeSecureScan.git
cd CodeSecureScan
pip install -r requirements.txt