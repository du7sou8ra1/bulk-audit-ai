"""Dev tool: does any detector fire on a Solidity source? Gap-hunting harness.

Usage:  ./venv/Scripts/python.exe gap_probe.py path/to/fixture.sol
Prints JSON: {"firing_detectors": [...], "reportable_detectors": [...], "covered": bool}

"covered" = at least one detector produced a candidate. "reportable_detectors" =
those that survive sanity/dedup and score to CONFIRMED_CRITICAL/LIKELY_CRITICAL.
"""
import json
import sys
from pathlib import Path

from backend.core import dedup
from backend.core.candidate_sanity import apply_candidate_sanity
from backend.core.precision_benchmark import REPORTABLE
from backend.core.scoring import mark_corroboration, score_finding
from backend.detectors.base import TargetContext
from backend.detectors.registry import get_detectors


def probe(src: str, profile: str = "ultra-deep-v2") -> dict:
    ctx = TargetContext(
        address="0x0000000000000000000000000000000000000001", chain="ethereum",
        profile=profile, onchain=None, proxy_info=None, workspace=Path("."),
        contract_name="T", source_files={"T.sol": src},
    )
    cands = []
    for d in get_detectors(profile):
        try:
            cands.extend(d.run(ctx))
        except Exception:
            pass
    firing = sorted({c.detector for c in cands})
    mark_corroboration(cands)
    cands = dedup.collapse_duplicates(cands)
    apply_candidate_sanity(ctx, cands)
    reportable = []
    for c in cands:
        if (c.evidence or {}).get("suppressed"):
            continue
        try:
            s = score_finding(c, [], profile=profile)
        except Exception:
            continue
        if s.classification in REPORTABLE:
            reportable.append(c.detector)
    return {
        "firing_detectors": firing,
        "reportable_detectors": sorted(set(reportable)),
        "covered": bool(firing),
    }


if __name__ == "__main__":
    text = Path(sys.argv[1]).read_text(encoding="utf-8") if len(sys.argv) > 1 else sys.stdin.read()
    print(json.dumps(probe(text)))
