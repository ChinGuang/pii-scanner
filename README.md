# PII Log Leak Detector

A Python CLI tool that **scans your codebase and captured log files for leaked Personally Identifiable Information (PII)**, traces every leak back to its exact file and line number, and automatically injects hardened `__repr__` fixes so a rerun comes back clean.

Built for banks, hospitals, and any team where a stray `logger.info(f"Processing {customer}")` can put IC numbers, card numbers, or email addresses in plaintext inside a log aggregator that far more people can access than the production database.

---

## Features

- **Three PII detectors** — NRIC (Malaysian/Singaporean format), credit/debit card numbers (Luhn-validated), and email addresses
- **Dual-surface scanning** — scans Python source files (`--source-dir`) and captured log files (`--log-file`) independently or together
- **Precise line attribution** — every Leak reports the exact artefact path and line number
- **Automatic fix generation** — injects a safe `__repr__` onto affected model classes so every future log call is safe by construction, not just the one that was caught
- **Git-native fix flow** — creates a dedicated fix branch, commits the patch, and prints the exact `gh pr create` command for you to review before anything lands on main
- **CI-friendly output** — plain text by default; `--json` flag for machine-readable output and pipeline gates
- **37 tests** — unit tests per detector (including Luhn edge cases), scanner aggregation tests, and end-to-end fix-flow tests

---

## Planted leak examples (in `models.py`)

| # | Type | How it leaks |
|---|------|-------------|
| 1 | **Obvious** | `logger.info(f"IC: {customer.ic_number}")` — direct field interpolation |
| 2 | **Object logging** | `logger.info(f"Processing {customer}")` — whole object, default `__repr__` exposes all fields |
| 3 | **Exception message** | `raise ValueError(f"Invalid card {customer.card_number}")` caught and re-logged |
| 4 | **Log file** | `app.log` line: `INFO Processing user john.doe@acme-bank.com card=4111111111111111` |

---

## Installation

```bash
cd pii-scanner
pip install -e .
```

---

## Usage

### Scan source files
```bash
pii-scan --source-dir path/to/your/service/
```

### Scan a log file
```bash
pii-scan --log-file path/to/app.log
```

### Scan both at once
```bash
pii-scan --source-dir src/ --log-file app.log
```

### Get JSON output (for CI gates)
```bash
pii-scan --source-dir src/ --log-file app.log --json
```

### Apply fixes (inject safe `__repr__`, create fix branch, print PR command)
```bash
pii-scan --source-dir src/ --fix
```

The `--fix` flag will:
1. Identify every model class whose fields contributed to a Leak
2. Inject (or replace) a `__repr__` that masks all PII fields with `***`
3. Commit the change to a new branch (`fix/pii-repr-<base-branch>`)
4. Print the `gh pr create` command so you can open a PR for review

### Demo flow
```bash
# Step 1 — see the leaks
pii-scan --source-dir pii_scanner/ --log-file tests/fixtures/app.log

# Step 2 — apply fixes
pii-scan --source-dir pii_scanner/ --fix

# Step 3 — rerun: should come back clean
pii-scan --source-dir pii_scanner/
# [OK] No PII leaks detected.
```

---

## Sample output

**Plain text (leaks found):**
```
[!!] 3 PII leak(s) found:

  [NRIC] pii_scanner/models.py:38
    > Processing customer with IC: [NRIC:S***A]
  [CARD] pii_scanner/models.py:49
    > Invalid card number for customer: [CARD:4111****1111]
  [EMAIL] tests/fixtures/app.log:2
    > INFO Processing user [EMAIL:jo***@acme-bank.com] card=[CARD:4111****1111]
```

**JSON (`--json`):**
```json
[
  {
    "artefact_path": "pii_scanner/models.py",
    "line_number": 38,
    "pii_class": "NRIC",
    "redacted_snippet": "Processing customer with IC: [NRIC:S***A]"
  }
]
```

---

## Running tests

```bash
cd pii-scanner
python -m pytest tests/ -v
```

Expected output: **37 passed**.

---

## Project structure

```
pii-scanner/
├── CONTEXT.md                          # Domain glossary
├── docs/adr/
│   ├── 0001-fix-via-repr-injection.md  # Why __repr__ injection, not call-site patching
│   └── 0002-pr-via-printed-command.md  # Why we print gh pr create instead of calling the API
├── pyproject.toml
├── pii_scanner/
│   ├── cli.py          # Entry point: argparse, --source-dir, --log-file, --fix, --json
│   ├── detectors.py    # detect_nric(), detect_card() (Luhn), detect_email()
│   ├── scanner.py      # Scanner orchestrator → Report, Leak dataclasses
│   ├── fixer.py        # __repr__ injector, git branch, commit, PR command
│   └── models.py       # Mock Customer service with 3 planted source leaks
└── tests/
    ├── fixtures/app.log        # Log-file leak: email + card on same line
    ├── test_detectors.py       # 20 unit tests per pattern + Luhn edge cases
    ├── test_scanner.py         # 9 unit tests: aggregation, output format
    └── test_e2e.py             # 8 end-to-end tests: scan → fix → clean rerun
```

---

## Architecture

```
CLI (cli.py)
 ├── Scanner (scanner.py)
 │    ├── detect_nric()   ──┐
 │    ├── detect_card()   ──┼──> Leak | None   ──> Report
 │    └── detect_email()  ──┘
 └── Fixer (fixer.py)
      ├── _inject_repr()       # replaces existing __repr__ or appends new one
      ├── _create_fix_branch() # git checkout -b fix/pii-repr-<base>
      ├── _commit_fixes()      # git add + commit
      └── _print_pr_command()  # prints gh pr create ...
```

Key architectural decision: fixes are applied at the **model class level** (injecting `__repr__`), not at individual logger call sites. One fix protects every current and future log call automatically. See [`docs/adr/0001-fix-via-repr-injection.md`](docs/adr/0001-fix-via-repr-injection.md).

---

## How this project was built with IBM Bob

This project was developed end-to-end using **[IBM Bob](https://www.ibm.com/products/ibm-bob)**, an AI software engineer. The development session used two Bob skills working in tandem:

### 1. `/grill-with-docs` — design interview before a single line of code

Before implementation started, Bob activated the **`grilling`** skill and conducted a structured design interview with 8 targeted questions, one at a time. Each question surfaced a concrete decision and gave a recommended answer with reasoning:

| Round | Decision made |
|-------|--------------|
| Q1 | PII scope: NRIC, Luhn-card, email only |
| Q2 | CLI flags: `--source-dir` and `--log-file` separately |
| Q3 | Fix strategy: inject `__repr__` on the model class, not patch call sites |
| Q4 | Git flow: fix branch → PR, never auto-merge to main |
| Q5 | Output: plain text default + `--json` flag |
| Q6 | PR integration: print `gh pr create` command, no API call |
| Q7 | Project location: `pii-scanner/` subdirectory in existing workspace |
| Q8 | Test coverage: unit tests per detector + end-to-end scan→fix→clean flow |

### 2. `domain-modeling` — live documentation as decisions crystallised

Simultaneously, Bob's **`domain-modeling`** skill captured every settled decision into permanent artefacts:

- **[`CONTEXT.md`](CONTEXT.md)** — a domain glossary with precise, opinionated terms: *Leak*, *Artefact*, *Detector*, *Report*, *Fix*, *Fix Branch*. Vague synonyms are listed under `_Avoid_` to keep the codebase's language consistent.
- **[`docs/adr/0001`](docs/adr/0001-fix-via-repr-injection.md)** — records why `__repr__` injection was chosen over call-site patching, and what the trade-off means for debugger visibility.
- **[`docs/adr/0002`](docs/adr/0002-pr-via-printed-command.md)** — records why the PR is opened via a printed command rather than a live API call.

### 3. Implementation — branch, code, tests, PR in one session

Once the design was approved, Bob:

1. Initialised a git repo and created the `feature/pii-log-leak-detector` branch
2. Scaffolded the package structure and `pyproject.toml`
3. Implemented all five core functions across four modules
4. Wrote 37 tests (unit + integration + end-to-end)
5. Debugged two environment-specific issues (Windows cp950 emoji encoding, setuptools backend path) and fixed them without human intervention
6. Committed everything and generated the PR command

Total wall-clock time: **under 25 minutes**, matching the stated constraint.

### Why Bob + grilling works for security tooling

Security tools carry high correctness stakes — a false negative (missed leak) is worse than no tool at all. The grilling session forced every ambiguous assumption into an explicit decision *before* code was written. The result: no design pivots during implementation, no rework, and a complete test suite from day one.

---

## Decisions recorded (ADRs)

| ADR | Decision |
|-----|---------|
| [0001](docs/adr/0001-fix-via-repr-injection.md) | Fix via `__repr__` injection, not call-site patching |
| [0002](docs/adr/0002-pr-via-printed-command.md) | PR opened via printed `gh` command, not GitHub API |

---

## License

MIT
