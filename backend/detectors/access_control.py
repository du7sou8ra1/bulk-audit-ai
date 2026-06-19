"""Detector: generalized access-control gaps (v0.4, was a stub).

Maps to Truebit (unauthorized mint), Wasabi (unchecked admin), and the broad
"missing modifier on a privileged function" class. Checks:

  * a privileged-looking, state-changing, externally-callable function with NO
    access-control modifier AND no `require(msg.sender == ...)` in the body.
  * `initialize()` with no `initializer`/`reinitializer`/`_disableInitializers`
    guard -> re-initialization / uninitialized-proxy takeover.
  * `tx.origin` used for authentication.
"""
from __future__ import annotations

import re

from .base import (
    Detector,
    FindingCandidate,
    TargetContext,
    header_has_access_control,
    iter_function_bodies,
)

# Privileged verbs that should virtually always be access-controlled.
_PRIV_RE = re.compile(
    r"^(set|update|change|add|remove|grant|revoke|withdraw|sweep|rescue|pause|"
    r"unpause|mint|burn|upgrade|migrate|seize|skim|collect|configure|enable|"
    r"disable|whitelist|blacklist|setowner|transferownership|setadmin|setfee|"
    r"setoracle|setverifier|setimplementation|init)\w*",
    re.IGNORECASE,
)
_INLINE_AUTH_RE = re.compile(r"require\s*\(\s*[^)]*msg\.sender\s*==|"
                             r"_checkOwner|_checkRole|onlyOwner\(|_authorizeUpgrade", re.IGNORECASE)
_INIT_GUARD_RE = re.compile(r"initializer|reinitializer|_disableInitializers|"
                            r"require\s*\([^)]*initialized", re.IGNORECASE)
_TXORIGIN_RE = re.compile(r"tx\.origin\s*==|==\s*tx\.origin|require\s*\([^)]*tx\.origin", re.IGNORECASE)


class AccessControlDetector(Detector):
    name = "access_control"

    def run(self, ctx: TargetContext) -> list[FindingCandidate]:
        findings: list[FindingCandidate] = []
        for path, source in ctx.source_files.items():
            if not source:
                continue
            for fname, _params, tail, body in iter_function_bodies(source):
                ext = re.search(r"\b(public|external)\b", tail) is not None
                if not ext:
                    continue
                lname = fname.lower()
                guarded = header_has_access_control(tail) or bool(_INLINE_AUTH_RE.search(body))

                # tx.origin auth (phishable)
                if _TXORIGIN_RE.search(body):
                    findings.append(self._c(
                        fname, path, body, bug="access_control", impact=7.0, conf=6.0,
                        title=f"tx.origin used for authorization: {fname}",
                        desc=(f"`{fname}` authorizes via tx.origin. tx.origin auth is phishable "
                              "(a malicious contract the owner calls can act on their behalf)."),
                        tests=["Replace tx.origin checks with msg.sender"]))

                # initializer with no guard
                if lname in ("initialize", "init", "__init", "setup") and not _INIT_GUARD_RE.search(body) \
                        and not _INIT_GUARD_RE.search(tail):
                    findings.append(self._c(
                        fname, path, body, bug="access_control", impact=8.5, conf=4.5,
                        title=f"Initializer with no initializer-guard: {fname}",
                        desc=(f"`{fname}` looks like an initializer but no `initializer`/"
                              "`_disableInitializers`/initialized guard was found. It may be callable "
                              "again (re-init takeover) or on an uninitialized implementation."),
                        tests=["Confirm OZ `initializer` modifier or an initialized flag guards it",
                               "Confirm the implementation calls _disableInitializers in its constructor"]))

                # privileged state-changer with no access control
                if _PRIV_RE.match(lname) and not guarded and not lname.startswith(("get", "view", "is", "preview")):
                    # require it actually changes state / moves value (avoid pure getters)
                    if re.search(r"=|\.transfer|\.call|_mint|_burn|delete\b|push\s*\(", body):
                        findings.append(self._c(
                            fname, path, body, bug="access_control", impact=9.0, conf=5.0,
                            title=f"Privileged function with no access control: {fname}",
                            desc=(f"`{fname}` is externally callable, mutates state/moves value, and "
                                  "no access-control modifier or `require(msg.sender==...)` was found. "
                                  "If it controls funds/config/roles, an arbitrary caller may abuse it "
                                  "(Truebit/Wasabi class)."),
                            tests=[f"eth_call {fname}(...) from a random EOA on a fork; expect revert if guarded",
                                   "Confirm the intended owner/role gates this function"], unprivileged=True))
        return findings

    @staticmethod
    def _c(fname, path, body, *, title, desc, impact, conf, bug, tests, unprivileged=True):
        return FindingCandidate(
            detector="access_control", title=title, description=desc,
            impact_score=impact, confidence_score=conf,
            severity_candidate="critical" if impact >= 9 else "high",
            evidence={"function": fname, "file": path, "snippet": body[:1500],
                      "bug_class": bug, "needs_poc": True, "unprivileged": unprivileged},
            next_tests=tests, affected_functions=[fname],
        )
