#!/usr/bin/env python3
from __future__ import annotations

import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
metadata = json.loads((ROOT / "project.json").read_text(encoding="utf-8"))
required = {
    "README.md",
    "AGENTS.md",
    "project.json",
    "pyproject.toml",
    ".zpkg.toml",
    "docs/test-strategy.md",
    "scripts/verify_repository.py",
    ".github/workflows/deep-tests.yml",
    "src/deep_tests/__init__.py",
}
missing = sorted(path for path in required if not (ROOT / path).exists())
if missing:
    raise SystemExit(f"missing required paths: {missing}")
if not (ROOT / "tests").is_dir() or not list((ROOT / "tests").glob("test_*.py")):
    raise SystemExit("at least one executable test module is required")

marker = re.compile(r"^(<{7}|={7}|>{7})", re.MULTILINE)
credential = re.compile(r"gh[pousr]_[A-Za-z0-9]{20,}|lin_api_[A-Za-z0-9]{20,}|BEGIN [A-Z ]*PRIVATE KEY")
for path in ROOT.rglob("*"):
    if not path.is_file() or ".git" in path.parts or path.stat().st_size > 1_000_000:
        continue
    try:
        text = path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        continue
    if marker.search(text):
        raise SystemExit(f"unresolved conflict marker: {path.relative_to(ROOT)}")
    if credential.search(text):
        raise SystemExit(f"credential-shaped content: {path.relative_to(ROOT)}")

agents = (ROOT / "AGENTS.md").read_text(encoding="utf-8")
for phrase in ("merge base", "3–10 relevant commits", "ours", "theirs", "Fail closed"):
    if phrase not in agents:
        raise SystemExit(f"semantic conflict policy missing phrase: {phrase}")

workflow = (ROOT / ".github/workflows/deep-tests.yml").read_text(encoding="utf-8")
if "permissions:\n  contents: read" not in workflow or "pull_request_target" in workflow:
    raise SystemExit("workflow permission boundary is unsafe")
action_pattern = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+@[0-9a-f]{40}$")
actions = [line.split("uses:", 1)[1].strip() for line in workflow.splitlines() if "uses:" in line]
if len(actions) < 2 or any(not action_pattern.fullmatch(action) for action in actions):
    raise SystemExit(f"workflow actions are not immutably pinned: {actions}")

if metadata.get("bootstrap_operation") != "deep-test-fleet-20260808":
    raise SystemExit("bootstrap operation identity drift")
if not str(metadata.get("organization", "")).endswith("-test"):
    raise SystemExit("repository is not bound to a test organization")
print(f"validated {metadata['organization']}/{metadata['repository']} suite={metadata['suite']}")
