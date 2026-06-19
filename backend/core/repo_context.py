"""Repository context ingestion (gap #5).

On-chain verified source has NO tests/docs. But a project's test suite encodes the
intended invariants and decimal conventions, and prior audit reports list
known/accepted issues — exactly what lets a refuter say "this is safe, proven by
relay.t.sol". When a GitHub URL is available for a target/protocol, this shallow-
clones it (read-only) and extracts a compact context: test files, docs, and
invariant hints, for the reasoner/refuter to cross-check against.

Opt-in: the on-chain-only flow has no repo URL, so this is driven by an optional
`github_url` on the scan/target. Safe: shallow clone to a temp dir, interactive
git prompts disabled, no build/execution, temp dir cleaned up.
"""
from __future__ import annotations

import logging
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

logger = logging.getLogger("bulkauditai.repo_context")

_TEST_MARKERS = (".t.sol", "test", "spec", "invariant")
_DOC_NAMES = ("readme", "security", "audit", "invariant", "spec", "whitepaper")


def _git_available() -> bool:
    return shutil.which("git") is not None


def fetch_repo_context(
    github_url: str,
    *,
    max_files: int = 40,
    max_chars: int = 60000,
    clone_timeout: int = 120,
) -> dict:
    """Shallow-clone a repo and extract tests + docs. Returns a context dict.

    Never raises; returns {"available": False, "reason": ...} on any failure."""
    if not github_url or not github_url.startswith(("https://github.com/", "http://github.com/")):
        return {"available": False, "reason": "no/invalid github url"}
    if not _git_available():
        return {"available": False, "reason": "git not installed"}

    tmp = tempfile.mkdtemp(prefix="bulkaudit_repo_")
    env = {**os.environ, "GIT_TERMINAL_PROMPT": "0", "GIT_ASKPASS": "echo"}
    try:
        proc = subprocess.run(
            ["git", "clone", "--depth", "1", github_url, tmp],
            capture_output=True, text=True, timeout=clone_timeout, env=env,
        )
        if proc.returncode != 0:
            return {"available": False, "reason": f"clone failed: {proc.stderr[:200]}"}

        root = Path(tmp)
        tests: dict[str, str] = {}
        docs: dict[str, str] = {}
        budget = max_chars

        for p in sorted(root.rglob("*")):
            if not p.is_file() or len(tests) + len(docs) >= max_files or budget <= 0:
                if len(tests) + len(docs) >= max_files or budget <= 0:
                    break
                continue
            rel = str(p.relative_to(root)).replace("\\", "/")
            low = rel.lower()
            if "/.git/" in "/" + low or "/node_modules/" in "/" + low or "/lib/" in "/" + low:
                continue
            is_test = low.endswith(".t.sol") or any(m in low for m in ("/test/", "/tests/")) and low.endswith(".sol")
            is_doc = low.endswith((".md", ".txt")) and any(d in low for d in _DOC_NAMES)
            if not (is_test or is_doc):
                continue
            try:
                content = p.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            take = content[: min(len(content), budget, 8000)]
            budget -= len(take)
            (tests if is_test else docs)[rel] = take

        # Cheap invariant hints: lines mentioning invariant / assert / "must".
        hints: list[str] = []
        for body in tests.values():
            for line in body.splitlines():
                ll = line.lower()
                if ("invariant" in ll or "asserteq" in ll or "must " in ll) and len(line) < 200:
                    hints.append(line.strip())
        return {
            "available": True,
            "github_url": github_url,
            "test_files": tests,
            "doc_files": docs,
            "invariant_hints": hints[:60],
        }
    except subprocess.TimeoutExpired:
        return {"available": False, "reason": "clone timed out"}
    except Exception as exc:  # noqa: BLE001
        return {"available": False, "reason": f"{type(exc).__name__}: {exc}"}
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
