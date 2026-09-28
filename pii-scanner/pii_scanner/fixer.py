"""
Fixer: injects a safe __repr__ onto affected model classes, creates a fix
branch, commits the changes, and prints the gh pr create command.
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

from pii_scanner.detectors import Leak

# Fields that must be masked in the injected __repr__
_PII_FIELDS = {"ic_number", "card_number", "email"}

# Marker inserted by the fixer so re-runs don't double-inject
_FIXER_MARKER = "# pii-scanner: safe __repr__ injected"

_REPR_TEMPLATE = '''\
    def __repr__(self) -> str:  {marker}
        safe = {{}}
        for k, v in self.__dict__.items():
            safe[k] = "***" if k in {pii_fields!r} else v
        return f"{{type(self).__name__}}({{', '.join(f'{{k}}={{v!r}}' for k, v in safe.items())}})"
'''


def _find_class_file(source_dir: str, class_name: str) -> Path | None:
    """Return the first .py file under *source_dir* that defines *class_name*."""
    pattern = re.compile(rf"^\s*class\s+{re.escape(class_name)}\s*[:(]")
    for py_path in Path(source_dir).rglob("*.py"):
        for line in py_path.read_text(encoding="utf-8", errors="replace").splitlines():
            if pattern.match(line):
                return py_path
    return None


def _inject_repr(file_path: Path, class_name: str) -> bool:
    """
    Inject a safe __repr__ into *class_name* inside *file_path*.

    Returns True if the file was modified, False if already patched or class not found.
    """
    source = file_path.read_text(encoding="utf-8")

    if _FIXER_MARKER in source:
        return False  # already patched

    class_re = re.compile(rf"^(\s*)class\s+{re.escape(class_name)}\s*[:(]", re.MULTILINE)
    match = class_re.search(source)
    if not match:
        return False

    pii_fields_set = _PII_FIELDS
    repr_code = _REPR_TEMPLATE.format(
        marker=_FIXER_MARKER,
        pii_fields=pii_fields_set,
    )

    # If an existing __repr__ is present inside this class, replace it entirely.
    existing_repr_re = re.compile(
        r"( {4}def __repr__\(self\)[^\n]*\n(?:(?! {0,3}\S).*\n)*)",
        re.MULTILINE,
    )
    new_source, n_replacements = existing_repr_re.subn(repr_code, source, count=1)
    if n_replacements == 0:
        # No existing __repr__ — append inside the class before the next top-level def
        insert_pos = len(source)
        after_class = source[match.end():]
        next_top = re.search(r"\n(?=\S)", after_class)
        if next_top:
            insert_pos = match.end() + next_top.start() + 1
        new_source = source[:insert_pos] + "\n" + repr_code + source[insert_pos:]

    file_path.write_text(new_source, encoding="utf-8")
    return True


def _git(args: list[str], cwd: str) -> str:
    result = subprocess.run(
        ["git"] + args, cwd=cwd, capture_output=True, text=True
    )
    return result.stdout.strip()


def apply_fixes(leaks: list[Leak], source_dir: str) -> str | None:
    """
    For each unique class affected by a Leak, inject a safe __repr__.
    Creates a fix branch, commits, and prints the gh pr create command.

    Returns the fix branch name, or None if no fixes were needed.
    """
    if not leaks:
        return None

    repo_root = _git(["rev-parse", "--show-toplevel"], cwd=source_dir)
    if not repo_root:
        repo_root = source_dir

    base_branch = _git(["rev-parse", "--abbrev-ref", "HEAD"], cwd=repo_root)
    fix_branch = f"fix/pii-repr-{base_branch.replace('/', '-')}"

    # Create fix branch from current HEAD
    _git(["checkout", "-b", fix_branch], cwd=repo_root)

    patched_any = False

    # Determine affected classes by scanning source for class definitions
    # near the leaking lines. Heuristic: find the class whose body contains
    # the leaking line.
    affected_classes: set[str] = set()
    for py_path in Path(source_dir).rglob("*.py"):
        source_text = py_path.read_text(encoding="utf-8", errors="replace")
        # Find all class definitions
        for m in re.finditer(r"^\s*class\s+(\w+)\s*[:(]", source_text, re.MULTILINE):
            class_name = m.group(1)
            # Check if this class's source contains PII fields
            class_body_start = m.start()
            next_class = re.search(r"^\s*class\s+\w+", source_text[m.end():], re.MULTILINE)
            class_body_end = (m.end() + next_class.start()) if next_class else len(source_text)
            class_body = source_text[class_body_start:class_body_end]
            if any(f"self.{field}" in class_body for field in _PII_FIELDS):
                affected_classes.add(class_name)

    for class_name in sorted(affected_classes):
        file_path = _find_class_file(source_dir, class_name)
        if file_path and _inject_repr(file_path, class_name):
            patched_any = True
            rel = str(file_path.relative_to(repo_root))
            _git(["add", rel], cwd=repo_root)

    if not patched_any:
        # Nothing to commit — return to base branch
        _git(["checkout", base_branch], cwd=repo_root)
        _git(["branch", "-D", fix_branch], cwd=repo_root)
        return None

    _git(
        ["commit", "-m", f"fix(pii): inject safe __repr__ on PII-bearing model classes"],
        cwd=repo_root,
    )

    pr_cmd = (
        f"gh pr create "
        f"--head {fix_branch} "
        f"--base {base_branch} "
        f'--title "fix(pii): safe __repr__ on PII-bearing models" '
        f'--body "Auto-generated by pii-scanner. Injects masked __repr__ to prevent PII leaking into logs."'
    )
    print("\n[OK] Fix committed to branch:", fix_branch)
    print("\n[PR] Open PR with:\n")
    print(f"    {pr_cmd}\n")

    return fix_branch
