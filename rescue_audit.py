#!/usr/bin/env python3
"""rescue-audit: a quick health check for codebases that were built in a hurry.

Scans a project directory for the problems that most often bite a fast-built
MVP once real users arrive: committed secrets, missing tests and CI, unpinned
dependencies, swallowed errors and debug settings left on.

Standard library only. Usage: python rescue_audit.py [path] [--json] [--strict]
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from dataclasses import asdict, dataclass
from pathlib import Path

__version__ = "0.1.0"

SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "env", "__pycache__", "dist", "build",
             ".next", ".nuxt", "target", "vendor", ".tox", ".mypy_cache", ".pytest_cache", "coverage"}
SOURCE_EXTS = {".py", ".js", ".jsx", ".ts", ".tsx", ".rb", ".go", ".java", ".kt", ".php", ".rs", ".swift", ".cs"}
TEXT_EXTS = SOURCE_EXTS | {".json", ".yml", ".yaml", ".toml", ".ini", ".cfg", ".env", ".sh", ".txt", ".md"}
MAX_BYTES = 1_000_000
LONG_FILE_LINES = 800
SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2}

SECRET_PATTERNS = [
    ("AWS access key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("private key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----")),
    ("API key", re.compile(r"\bsk-[A-Za-z0-9_\-]{24,}\b")),
    ("hardcoded credential", re.compile(
        r"""(?i)\b(?:api[_-]?key|secret|passwd|password|auth[_-]?token|access[_-]?token)\b\s*[:=]\s*['"][^'"\s]{12,}['"]""")),
]
PLACEHOLDER = re.compile(r"(?i)(example|changeme|change_me|placeholder|your[_-]|xxxx|<[^>]+>|\$\{|process\.env|os\.environ)")
DEBUG_PATTERNS = re.compile(r"(?m)^\s*DEBUG\s*=\s*True\b|\bdebug\s*=\s*True\b|\bapp\.run\([^)]*debug\s*=\s*True")
BARE_EXCEPT = re.compile(r"(?m)^\s*except\s*:\s*$|^\s*except\s+Exception(?:\s+as\s+\w+)?\s*:\s*\n\s*pass\b")
EMPTY_CATCH = re.compile(r"catch\s*(?:\([^)]*\))?\s*\{\s*\}")
TODO = re.compile(r"\b(?:TODO|FIXME|HACK|XXX)\b")
TEST_FILE = re.compile(r"(?i)(^test_.*\.py$|_test\.(py|go)$|\.(test|spec)\.[jt]sx?$|_spec\.rb$|Tests?\.(java|kt|cs)$)")
UNPINNED_REQ = re.compile(r"^[A-Za-z0-9_.\-\[\]]+\s*(?:>=|>|~=|$)")
CI_PATHS = [".github/workflows", ".gitlab-ci.yml", ".circleci", "Jenkinsfile", "azure-pipelines.yml",
            "bitbucket-pipelines.yml", ".buildkite"]
LOCKFILES = {"package.json": ["package-lock.json", "yarn.lock", "pnpm-lock.yaml", "bun.lockb", "bun.lock"],
             "Pipfile": ["Pipfile.lock"], "Gemfile": ["Gemfile.lock"]}


@dataclass
class Finding:
    severity: str
    check: str
    message: str
    path: str = ""
    line: int = 0


def iter_files(root: Path):
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)
        for name in sorted(filenames):
            yield Path(dirpath) / name


def read_text(path: Path) -> str | None:
    try:
        if path.stat().st_size > MAX_BYTES:
            return None
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return None


def is_minified(name: str, text: str) -> bool:
    """Bundled or minified output is generated code; reviewing it line by line is noise."""
    if ".min." in name:
        return True
    lines = text.count("\n") + 1
    return len(text) > 5000 and len(text) / lines > 500


def line_of(text: str, pos: int) -> int:
    return text.count("\n", 0, pos) + 1


def audit(root: Path) -> list[Finding]:
    root = Path(root)
    findings: list[Finding] = []
    has_tests = False
    todo_count = 0
    source_files = 0

    for path in iter_files(root):
        rel = path.relative_to(root).as_posix()
        name = path.name
        if TEST_FILE.search(name) or "/tests/" in f"/{rel}" or "/__tests__/" in f"/{rel}":
            has_tests = True
        if name == ".env" or (name.startswith(".env.") and not name.endswith((".example", ".sample", ".template"))):
            findings.append(Finding("high", "env-file", "Environment file is in the project tree; make sure it is not committed", rel))
        if path.suffix not in TEXT_EXTS and not name.startswith(".env"):
            continue
        text = read_text(path)
        if text is None:
            continue
        is_test = TEST_FILE.search(name) is not None

        for label, pattern in SECRET_PATTERNS:
            for m in pattern.finditer(text):
                if PLACEHOLDER.search(m.group(0)) or is_test:
                    continue
                findings.append(Finding("high", "secret", f"Possible {label} in source", rel, line_of(text, m.start())))

        if path.suffix in SOURCE_EXTS:
            if is_minified(name, text):
                continue
            source_files += 1
            todo_count += len(TODO.findall(text))
            lines = text.count("\n") + 1
            if lines > LONG_FILE_LINES:
                findings.append(Finding("low", "long-file", f"{lines} lines; hard to review and change safely", rel))
            if not is_test:
                for m in DEBUG_PATTERNS.finditer(text):
                    findings.append(Finding("medium", "debug", "Debug mode switched on in code", rel, line_of(text, m.start())))
                swallow = BARE_EXCEPT if path.suffix == ".py" else EMPTY_CATCH
                for m in swallow.finditer(text):
                    findings.append(Finding("medium", "swallowed-error", "Error is caught and ignored", rel, line_of(text, m.start())))

        if name == "requirements.txt":
            loose = [ln.strip() for ln in text.splitlines()
                     if ln.strip() and not ln.strip().startswith(("#", "-")) and UNPINNED_REQ.match(ln.strip())]
            if loose:
                findings.append(Finding("medium", "unpinned-deps",
                                        f"{len(loose)} dependencies without an exact version (e.g. {loose[0]})", rel))
        if name in LOCKFILES and not any((path.parent / lock).exists() for lock in LOCKFILES[name]):
            findings.append(Finding("medium", "no-lockfile", f"{name} has no lockfile next to it; installs are not reproducible", rel))

    if source_files and not has_tests:
        findings.append(Finding("high", "no-tests", "No automated tests found"))
    if source_files and not any((root / p).exists() for p in CI_PATHS):
        findings.append(Finding("medium", "no-ci", "No CI configuration found; nothing runs checks before a deploy"))
    if not any((root / n).exists() for n in ("README.md", "README.rst", "README.txt", "README")):
        findings.append(Finding("low", "no-readme", "No README; setup steps live in someone's head"))
    if source_files and not (root / ".gitignore").exists():
        findings.append(Finding("low", "no-gitignore", "No .gitignore; build output and local config can end up committed"))
    if todo_count >= 20:
        findings.append(Finding("low", "todo-debt", f"{todo_count} TODO/FIXME markers across the code"))

    findings.sort(key=lambda f: (SEVERITY_ORDER[f.severity], f.check, f.path, f.line))
    return findings


def render(findings: list[Finding], root: Path) -> str:
    if not findings:
        return f"rescue-audit: no problems found in {root}"
    noun = "finding" if len(findings) == 1 else "findings"
    out = [f"rescue-audit: {len(findings)} {noun} in {root}", ""]
    for sev in ("high", "medium", "low"):
        group = [f for f in findings if f.severity == sev]
        if not group:
            continue
        out.append(f"{sev.upper()} ({len(group)})")
        for f in group:
            where = f"  {f.path}" + (f":{f.line}" if f.line else "") if f.path else ""
            out.append(f"  [{f.check}] {f.message}{where}")
        out.append("")
    return "\n".join(out).rstrip()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="rescue-audit", description=__doc__.splitlines()[0])
    parser.add_argument("path", nargs="?", default=".", help="project directory to scan (default: current directory)")
    parser.add_argument("--json", action="store_true", help="print findings as JSON")
    parser.add_argument("--strict", action="store_true", help="exit with status 1 if any high-severity finding exists")
    parser.add_argument("--version", action="version", version=__version__)
    args = parser.parse_args(argv)

    root = Path(args.path)
    if not root.is_dir():
        print(f"rescue-audit: {root} is not a directory", file=sys.stderr)
        return 2
    findings = audit(root)
    if args.json:
        print(json.dumps([asdict(f) for f in findings], indent=2))
    else:
        print(render(findings, root))
    return 1 if args.strict and any(f.severity == "high" for f in findings) else 0


if __name__ == "__main__":
    sys.exit(main())
