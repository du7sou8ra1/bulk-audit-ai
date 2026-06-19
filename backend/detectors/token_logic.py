"""Detector: token logic (mint/burn/transfer) abuse (v0.4, was a stub).

Maps to SOF/LAXO (burn-mechanism flaw + price manipulation). Checks:

  * burn that reduces a balance/supply used in price/share math -> burn-to-pump.
  * unchecked transfer/transferFrom return value (silent failure).
  * fee-on-transfer mismatch: transferFrom(amount) then credit `amount` without
    measuring the actually-received delta.
  * ERC777/ERC1363 callback hooks (tokensReceived/onTransferReceived) that can
    re-enter while balances are mid-update.
"""
from __future__ import annotations

import re

from .base import Detector, FindingCandidate, TargetContext, iter_function_bodies

_BURN_RE = re.compile(r"_burn\s*\(|\bburn\s*\(|balances?\[[^\]]*\]\s*-=|totalSupply\s*-=", re.IGNORECASE)
_PRICEY_RE = re.compile(r"price|share|rate|reserve|getAmountsOut|balanceOf", re.IGNORECASE)
_UNCHECKED_TRANSFER_RE = re.compile(
    r"(?<![=!<>])\b\w+\.transfer(From)?\s*\([^;]*\)\s*;", re.IGNORECASE
)
_SAFE_RE = re.compile(r"safeTransfer|require\s*\([^)]*transfer|bool\s+\w+\s*=\s*\w+\.transfer", re.IGNORECASE)
_FOT_RE = re.compile(r"transferFrom\s*\(", re.IGNORECASE)
_BALANCE_DELTA_RE = re.compile(r"balanceOf\s*\([^)]*\)\s*-|received\s*=|after\s*-\s*before", re.IGNORECASE)
_HOOK_RE = re.compile(r"tokensReceived|tokensToSend|onTransferReceived|_callTokensReceived|ERC777", re.IGNORECASE)


class TokenLogicDetector(Detector):
    name = "token_logic"

    def run(self, ctx: TargetContext) -> list[FindingCandidate]:
        text = ctx.all_source_text()
        low = (text or "").lower()
        if not text or not any(k in low for k in ("token", "erc20", "mint", "burn", "transfer", "supply")):
            return []
        findings: list[FindingCandidate] = []
        for path, source in ctx.source_files.items():
            if not source:
                continue
            for fname, _params, _tail, body in iter_function_bodies(source):
                # 1) burn that feeds price/share math (burn-to-pump)
                if _BURN_RE.search(body) and _PRICEY_RE.search(body):
                    findings.append(self._c(
                        fname, path, body, bug="oracle", impact=7.5, conf=4.0,
                        title=f"Burn affects price/share math: {fname}",
                        desc=(f"`{fname}` burns/reduces a balance or supply that also feeds a "
                              "price/share/reserve calculation. A flawed burn mechanism lets an "
                              "attacker pump price by destroying supply (SOF/LAXO class)."),
                        tests=["Model burn -> price impact on a fork and check for profitable round-trip"]))
                # 2) unchecked transfer return
                if _UNCHECKED_TRANSFER_RE.search(body) and not _SAFE_RE.search(body):
                    findings.append(self._c(
                        fname, path, body, bug="token", impact=5.0, conf=4.0,
                        title=f"Unchecked ERC20 transfer return value: {fname}",
                        desc=(f"`{fname}` calls transfer/transferFrom without checking the bool "
                              "return (and not via SafeERC20). Non-reverting tokens can silently "
                              "fail, breaking accounting."),
                        tests=["Use SafeERC20 or require the return value"], unprivileged=False))
                # 3) fee-on-transfer mismatch
                if _FOT_RE.search(body) and not _BALANCE_DELTA_RE.search(body) and _PRICEY_RE.search(body):
                    findings.append(self._c(
                        fname, path, body, bug="token", impact=6.0, conf=3.5,
                        title=f"Possible fee-on-transfer accounting mismatch: {fname}",
                        desc=(f"`{fname}` pulls tokens via transferFrom and appears to credit the "
                              "requested amount without measuring the actually-received delta. "
                              "Fee-on-transfer/deflationary tokens credit more than received."),
                        tests=["Measure balanceOf(this) before/after and credit the delta"]))
                # 4) ERC777/callback hook re-entry
                if _HOOK_RE.search(body):
                    findings.append(self._c(
                        fname, path, body, bug="reentrancy", impact=6.5, conf=3.5,
                        title=f"ERC777/callback hook in token flow: {fname}",
                        desc=(f"`{fname}` involves an ERC777/ERC1363 transfer hook. These hand "
                              "control to the recipient mid-transfer and have enabled reentrancy "
                              "drains; ensure CEI + nonReentrant around it."),
                        tests=["Fork-test a malicious hook that re-enters during the transfer"]))
        return findings

    @staticmethod
    def _c(fname, path, body, *, title, desc, impact, conf, bug, tests, unprivileged=True):
        return FindingCandidate(
            detector="token_logic", title=title, description=desc,
            impact_score=impact, confidence_score=conf,
            severity_candidate="critical" if impact >= 9 else ("high" if impact >= 7 else "medium"),
            evidence={"function": fname, "file": path, "snippet": body[:1500],
                      "bug_class": bug, "needs_poc": True, "unprivileged": unprivileged},
            next_tests=tests, affected_functions=[fname],
        )
