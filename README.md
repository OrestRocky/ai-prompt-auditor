 AI Prompt Auditor

A lightweight CLI tool that scans text (prompts, notes, logs, drafts) for accidental leakage of sensitive data such as API keys, tokens, seed phrases, private keys, emails, and other high-risk artifacts — and returns a clear, action-oriented risk report.

This project is designed for real-world workflows where people copy/paste between chats, docs, tickets, and AI tools, and where “one small slip” becomes an irreversible incident.

---

## Why this exists

Modern “private secrets” (seed phrases, private keys, recovery codes, API tokens) are a new class of assets:
- small in footprint (often a short string),
- high in value (financial, legal, personal),
- and frequently irreversible if leaked or lost.

The problem is not that people are careless — it’s that secrets now migrate across devices, apps, and contexts that were not built for high-assurance custody.

`ai-prompt-auditor` is a practical guardrail: it helps you catch dangerous artifacts *before* they leave your control.

---

## What it does

Given an input text, the auditor:
- detects known secret/PII patterns (configurable),
- assigns a **risk score**,
- returns **findings** (type, severity, count),
- provides **recommended actions** (revoke/rotate/redact).

---

## Quick start

### Requirements
- Python 3.10+

### Install (local)
```bash
git clone https://github.com/OrestRocky/ai-prompt-auditor.git
cd ai-prompt-auditor
python3 -m venv .venv
source .venv/bin/activate
````

### Run

```bash
python -m src.cli --text "my api_key='ABCDEF1234567890XYZ' and email=test@example.com"
```

---

## Output format (example)

Typical output includes:

* `RISK SCORE: X/100`
* `FINDINGS:` list with severity and matches
* `RECOMMENDATIONS:` clear mitigation steps

---

## What it detects (typical categories)

* Credentials & secrets: API keys, tokens, private keys, seed phrases (where possible), authorization headers
* Personal data: emails and common PII patterns (optional / configurable)
* High-risk strings: suspicious assignments like `api_key=...`, `token: ...`, etc.

> Note: This tool is a **pattern-based auditor**, not a cryptographic verifier. It is intended to reduce common operational leaks.

---

## Recommended operational use

Use it to scan:

* prompts before sending them to AI assistants,
* customer support tickets,
* incident notes,
* onboarding docs,
* internal chat exports,
* copied snippets from terminals/configs.

A simple rule: **If it leaves your system, it must be scanned.**

---

## Project structure

```
ai-prompt-auditor/
  README.md
  requirements.txt
  src/
    __init__.py
    cli.py
    audit.py
    patterns.py
```

---

## Roadmap

* [ ] `--redact` mode to produce a clean, safe version of the text
* [ ] Policy profiles: `personal / enterprise / legal / AI-vendor`
* [ ] JSON output mode for CI / pipelines
* [ ] File input support: `--file path.txt`
* [ ] Custom rules via YAML/JSON config
* [ ] Unit tests + baseline datasets

---

## Security notes

* This tool should be treated as a **preventive control**, not a guarantee.
* If a secret is detected in shared text: assume compromise, rotate/revoke, and audit access logs.
* Avoid feeding real secrets into public services during testing; use synthetic placeholders.

---

## License

MIT (or choose your preferred license).

```

Якщо хочеш, я можу одразу підготувати:
1) **короткий “Executive README”** (на 15 рядків для клієнта/інвестора)  
2) **розширений README** з `--redact`, `--json`, прикладами і “policy profiles” (і ми це потім реалізуємо)

Скажи: **“короткий”** або **“розширений”**.
::contentReference[oaicite:0]{index=0}
```

