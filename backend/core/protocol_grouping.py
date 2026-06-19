"""Protocol grouping (gap #4).

Real bugs are protocol-level (vault<->accountant<->teller; commit<->verify<->execute
across contracts). The scanner audits one address at a time; this clusters a bulk
address list into *protocols* so related contracts can later be reasoned about with
shared context. Three signals, best-effort:

  1. shared deployer (Etherscan `getcontractcreation`)
  2. proxy -> implementation edges
  3. cross-references (one contract's address literal appears in another's source)

This is a foundation helper: `group_targets()` returns clusters that the API/CLI
can use to drive a protocol-aware scan. It performs only read-only explorer reads.
"""
from __future__ import annotations

import logging

import requests

from ..config import get_settings

logger = logging.getLogger("bulkauditai.grouping")


def _norm(addr: str) -> str:
    return (addr or "").strip().lower()


def get_deployers(addresses: list[str], chain: str = "ethereum") -> dict[str, str]:
    """address -> deployer (best effort, via Etherscan getcontractcreation)."""
    s = get_settings()
    out: dict[str, str] = {}
    if not s.etherscan_api_key or not addresses:
        return out
    # Etherscan accepts up to 5 addresses per getcontractcreation call.
    for i in range(0, len(addresses), 5):
        batch = addresses[i : i + 5]
        try:
            resp = requests.get(
                s.etherscan_base_url,
                params={
                    "chainid": s.etherscan_chain_id(chain),
                    "module": "contract",
                    "action": "getcontractcreation",
                    "contractaddresses": ",".join(batch),
                    "apikey": s.etherscan_api_key,
                },
                timeout=30,
            )
            resp.raise_for_status()
            result = resp.json().get("result")
            if isinstance(result, list):
                for row in result:
                    a = _norm(row.get("contractAddress", ""))
                    d = _norm(row.get("contractCreator", ""))
                    if a and d:
                        out[a] = d
        except Exception as exc:  # noqa: BLE001
            logger.info("getcontractcreation failed: %s", exc)
    return out


class _DSU:
    def __init__(self, items: list[str]) -> None:
        self.parent = {x: x for x in items}

    def find(self, x: str) -> str:
        while self.parent[x] != x:
            self.parent[x] = self.parent[self.parent[x]]
            x = self.parent[x]
        return x

    def union(self, a: str, b: str) -> None:
        if a in self.parent and b in self.parent:
            self.parent[self.find(a)] = self.find(b)


def group_targets(
    addresses: list[str],
    *,
    chain: str = "ethereum",
    proxy_impl_edges: dict[str, str] | None = None,
    source_by_addr: dict[str, str] | None = None,
) -> list[list[str]]:
    """Cluster addresses into protocols. Returns a list of address groups."""
    addrs = [_norm(a) for a in addresses if a]
    addrs = list(dict.fromkeys(addrs))  # dedupe, keep order
    if len(addrs) <= 1:
        return [addrs] if addrs else []

    dsu = _DSU(addrs)

    # (1) shared deployer
    deployers = get_deployers(addrs, chain)
    by_deployer: dict[str, list[str]] = {}
    for a, d in deployers.items():
        by_deployer.setdefault(d, []).append(a)
    for group in by_deployer.values():
        for x in group[1:]:
            dsu.union(group[0], x)

    # (2) proxy -> implementation edges (if both are in the set)
    for proxy, impl in (proxy_impl_edges or {}).items():
        dsu.union(_norm(proxy), _norm(impl))

    # (3) cross-references in source
    if source_by_addr:
        addr_set = set(addrs)
        for a, src in source_by_addr.items():
            low = (src or "").lower()
            for other in addr_set:
                if other != _norm(a) and other in low:
                    dsu.union(_norm(a), other)

    clusters: dict[str, list[str]] = {}
    for a in addrs:
        clusters.setdefault(dsu.find(a), []).append(a)
    # Largest protocols first.
    return sorted(clusters.values(), key=len, reverse=True)
