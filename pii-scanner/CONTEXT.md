# PII Log Leak Detector

A CLI tool that scans Python source files and captured log files for leaked Personally Identifiable Information (PII), traces each leak to its origin line, injects safe `__repr__` fixes, and opens a PR for review.

## Language

**PII Pattern**:
A compiled regular expression (or Luhn-checksum rule) that recognises a specific class of sensitive data — NRIC, card number, or email address — in a string of text.
_Avoid_: rule, matcher, regex

**Leak**:
A finding where a PII Pattern matches content in a scanned artefact (source file or log file). A Leak carries the artefact path, line number, matched PII class, and the redacted snippet.
_Avoid_: hit, match, violation, finding

**Artefact**:
A file submitted for scanning. Two kinds exist: a Source Artefact (`.py` file) and a Log Artefact (`.log` / plaintext captured output).
_Avoid_: target, input file

**Scanner**:
The orchestrator that accepts a source directory and an optional log file, delegates line-by-line detection to Detectors, and aggregates the resulting Leaks into a Report.
_Avoid_: engine, runner, analyser

**Detector**:
A single-responsibility function that tests one line of text against one PII Pattern and returns a Leak or nothing.
_Avoid_: checker, validator, rule

**Report**:
The aggregated, ordered list of Leaks produced by a Scanner run. Rendered as plain text by default; as JSON when `--json` is passed.
_Avoid_: output, result, findings

**Fix**:
A source-code patch that injects a safe `__repr__` method onto a model class, preventing the class from ever emitting PII when logged. A Fix is generated per affected class, not per Leak.
_Avoid_: patch, remediation, rewrite

**Fix Branch**:
A short-lived git branch created from the current working branch, onto which all Fixes for a scan run are committed. The CLI prints the `gh pr create` command needed to open a PR from Fix Branch → working branch.
_Avoid_: patch branch, hotfix branch
