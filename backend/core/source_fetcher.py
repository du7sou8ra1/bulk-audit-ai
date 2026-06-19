"""Fetch verified source, ABI and bytecode from Etherscan (v2 multichain API).

Handles every Etherscan source shape:
  1. unverified (empty SourceCode)
  2. single-file Solidity
  3. multi-file JSON  ({ "path.sol": {"content": ...}, ... })
  4. standard-json input (wrapped in extra braces: {{ ... }})
  5. proxy contracts (Implementation address surfaced for follow-up fetch)

If parsing fails we still persist the raw payload and continue with
bytecode/on-chain checks — a fetch problem must never abort a scan.
"""
from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path

import requests

from ..config import get_settings

logger = logging.getLogger("bulkauditai.source_fetcher")


@dataclass
class SourcePackage:
    address: str
    verified: bool = False
    contract_name: str = ""
    compiler_version: str = ""
    evm_version: str = ""
    optimization_used: bool = False
    optimization_runs: int = 0
    source_files: dict[str, str] = field(default_factory=dict)
    abi: list | dict | None = None
    is_proxy: bool = False
    implementation: str | None = None
    raw_source_code: str = ""
    error: str | None = None

    @property
    def solc_version(self) -> str | None:
        """Extract a bare semver like '0.8.19' from the compiler string."""
        m = re.search(r"(\d+\.\d+\.\d+)", self.compiler_version or "")
        return m.group(1) if m else None


def _sanitize_relpath(name: str) -> str:
    """Make an Etherscan source key safe to write under a workspace."""
    name = name.replace("\\", "/").lstrip("/")
    parts = [p for p in name.split("/") if p not in ("", ".", "..")]
    safe = "/".join(parts) or "Contract.sol"
    if not safe.endswith(".sol"):
        safe += ".sol"
    return safe


def _parse_source_code(source_code: str, contract_name: str) -> dict[str, str]:
    """Turn the Etherscan SourceCode field into {relative_path: content}."""
    source_code = source_code or ""
    if not source_code.strip():
        return {}

    text = source_code.strip()

    # Case: standard-json wrapped in an extra pair of braces: {{ ... }}
    if text.startswith("{{") and text.endswith("}}"):
        text = text[1:-1]

    # Try to interpret as JSON (standard-json input or multi-file map).
    if text.startswith("{"):
        try:
            parsed = json.loads(text)
        except json.JSONDecodeError:
            parsed = None

        if isinstance(parsed, dict):
            # standard-json input -> {"sources": {"path": {"content": ...}}}
            sources = parsed.get("sources")
            if isinstance(sources, dict):
                out: dict[str, str] = {}
                for path, entry in sources.items():
                    if isinstance(entry, dict) and "content" in entry:
                        out[_sanitize_relpath(path)] = entry["content"]
                if out:
                    return out
            # plain multi-file map -> {"path": {"content": ...}} or {"path": "..."}
            out = {}
            for path, entry in parsed.items():
                if isinstance(entry, dict) and "content" in entry:
                    out[_sanitize_relpath(path)] = entry["content"]
                elif isinstance(entry, str):
                    out[_sanitize_relpath(path)] = entry
            if out:
                return out

    # Fallback: single-file Solidity source.
    fname = _sanitize_relpath(contract_name or "Contract")
    return {fname: source_code}


def _etherscan_get(params: dict) -> dict | None:
    s = get_settings()
    if not s.etherscan_api_key:
        logger.warning("ETHERSCAN_API_KEY not set; cannot fetch source")
        return None
    query = {
        "chainid": s.etherscan_chain_id(params.pop("chain", None)),
        "apikey": s.etherscan_api_key,
        **params,
    }
    try:
        resp = requests.get(s.etherscan_base_url, params=query, timeout=30)
        resp.raise_for_status()
        return resp.json()
    except Exception as exc:
        logger.warning("etherscan request failed: %s", exc)
        return None


def fetch_etherscan_source(address: str, chain: str = "ethereum") -> SourcePackage:
    pkg = SourcePackage(address=address)
    data = _etherscan_get(
        {"module": "contract", "action": "getsourcecode", "address": address, "chain": chain}
    )
    if not data:
        pkg.error = "etherscan request failed or API key missing"
        return pkg

    result = data.get("result")
    if not isinstance(result, list) or not result:
        pkg.error = f"unexpected etherscan response: {str(data)[:200]}"
        return pkg

    entry = result[0]
    pkg.raw_source_code = entry.get("SourceCode", "") or ""
    pkg.contract_name = entry.get("ContractName", "") or ""
    pkg.compiler_version = entry.get("CompilerVersion", "") or ""
    pkg.evm_version = entry.get("EVMVersion", "") or ""
    pkg.optimization_used = entry.get("OptimizationUsed", "0") == "1"
    try:
        pkg.optimization_runs = int(entry.get("Runs") or 0)
    except (TypeError, ValueError):
        pkg.optimization_runs = 0
    pkg.is_proxy = entry.get("Proxy", "0") == "1"
    impl = entry.get("Implementation", "") or ""
    pkg.implementation = impl if impl and int(impl, 16) != 0 else None

    abi_raw = entry.get("ABI", "")
    if abi_raw and abi_raw != "Contract source code not verified":
        try:
            pkg.abi = json.loads(abi_raw)
        except json.JSONDecodeError:
            pkg.abi = None

    if not pkg.raw_source_code.strip():
        pkg.verified = False
        pkg.error = "source not verified on explorer"
        return pkg

    pkg.verified = True
    try:
        pkg.source_files = _parse_source_code(pkg.raw_source_code, pkg.contract_name)
    except Exception as exc:  # pragma: no cover - defensive
        logger.warning("source parse failed for %s: %s", address, exc)
        pkg.error = f"source parse failed: {exc}"
        pkg.source_files = {
            _sanitize_relpath(pkg.contract_name or "Contract"): pkg.raw_source_code
        }
    return pkg


def fetch_etherscan_abi(address: str, chain: str = "ethereum") -> list | dict | None:
    data = _etherscan_get(
        {"module": "contract", "action": "getabi", "address": address, "chain": chain}
    )
    if not data:
        return None
    result = data.get("result")
    if not result or result == "Contract source code not verified":
        return None
    try:
        return json.loads(result)
    except (json.JSONDecodeError, TypeError):
        return None


def fetch_deployer_creations(
    deployer: str, chain: str = "ethereum", start_block: int = 0
) -> list[tuple[str, int]]:
    """Contracts created by ``deployer`` since ``start_block``.

    Returns [(contract_address_lowercase, block_number)] sorted by block. Covers
    both direct deploys (normal txlist, ``to`` empty) and factory/internal deploys
    (txlistinternal, ``type`` == create). Used by the new-deployment watcher.
    """
    found: dict[str, int] = {}

    direct = _etherscan_get({
        "module": "account", "action": "txlist", "address": deployer,
        "startblock": start_block, "endblock": 99999999, "sort": "asc", "chain": chain,
    })
    for t in (direct or {}).get("result") or []:
        if not isinstance(t, dict):
            continue
        addr = t.get("contractAddress") or ""
        if t.get("to") in ("", None) and addr and addr != "0x":
            try:
                if int(addr, 16) != 0:
                    found[addr.lower()] = int(t.get("blockNumber") or 0)
            except ValueError:
                pass

    internal = _etherscan_get({
        "module": "account", "action": "txlistinternal", "address": deployer,
        "startblock": start_block, "endblock": 99999999, "sort": "asc", "chain": chain,
    })
    for t in (internal or {}).get("result") or []:
        if not isinstance(t, dict):
            continue
        addr = t.get("contractAddress") or ""
        if str(t.get("type", "")).startswith("create") and addr:
            try:
                if int(addr, 16) != 0:
                    found.setdefault(addr.lower(), int(t.get("blockNumber") or 0))
            except ValueError:
                pass

    return sorted(found.items(), key=lambda kv: kv[1])


# --------------------------------------------------------------------------- #
# Sourcify fallback (gap #8) — keyless, verified-source mirror. Used when
# Etherscan is unverified / errored / rate-limited.
# --------------------------------------------------------------------------- #
_SOURCIFY_SERVER = "https://sourcify.dev/server"


def fetch_sourcify_source(address: str, chain: str = "ethereum") -> SourcePackage | None:
    pkg = SourcePackage(address=address)
    chain_id = get_settings().etherscan_chain_id(chain)  # same numeric ids
    try:
        resp = requests.get(
            f"{_SOURCIFY_SERVER}/files/any/{chain_id}/{address}", timeout=30
        )
        if resp.status_code != 200:
            return None
        data = resp.json()
    except Exception as exc:  # noqa: BLE001
        logger.info("sourcify fetch failed for %s: %s", address, exc)
        return None

    files = data.get("files") if isinstance(data, dict) else None
    if not files:
        return None

    sources: dict[str, str] = {}
    metadata_json: dict | None = None
    for f in files:
        name = f.get("name", "")
        content = f.get("content", "")
        if name.endswith(".sol") and content:
            rel = _sanitize_relpath(f.get("path") or name)
            sources[rel] = content
        elif name == "metadata.json" and content:
            try:
                metadata_json = json.loads(content)
            except json.JSONDecodeError:
                metadata_json = None
    if not sources:
        return None

    pkg.verified = True
    pkg.source_files = sources
    pkg.raw_source_code = next(iter(sources.values()), "")
    if metadata_json:
        comp = (metadata_json.get("compiler") or {}).get("version", "")
        pkg.compiler_version = comp
        settings_meta = metadata_json.get("settings") or {}
        pkg.evm_version = settings_meta.get("evmVersion", "") or ""
        opt = settings_meta.get("optimizer") or {}
        pkg.optimization_used = bool(opt.get("enabled"))
        try:
            pkg.optimization_runs = int(opt.get("runs") or 0)
        except (TypeError, ValueError):
            pkg.optimization_runs = 0
        out = (metadata_json.get("output") or {})
        abi = out.get("abi")
        if isinstance(abi, list):
            pkg.abi = abi
        # contract name: take from compilationTarget if present
        target = settings_meta.get("compilationTarget") or {}
        if isinstance(target, dict) and target:
            pkg.contract_name = next(iter(target.values()), "") or pkg.contract_name
    return pkg


def fetch_source(address: str, chain: str = "ethereum") -> SourcePackage:
    """Etherscan first; Sourcify fallback when unverified/errored.

    Drop-in replacement for ``fetch_etherscan_source`` (same return type) — the
    scanner should call this so a single explorer failure doesn't blind the scan.
    """
    pkg = fetch_etherscan_source(address, chain)
    if pkg.verified and pkg.source_files:
        return pkg
    if not get_settings().enable_sourcify:
        return pkg
    alt = fetch_sourcify_source(address, chain)
    if alt and alt.verified and alt.source_files:
        # preserve proxy/impl info etherscan may have surfaced
        alt.is_proxy = pkg.is_proxy or alt.is_proxy
        alt.implementation = pkg.implementation or alt.implementation
        if pkg.abi is not None and alt.abi is None:
            alt.abi = pkg.abi
        alt.error = None
        logger.info("source for %s recovered via Sourcify fallback", address)
        return alt
    return pkg


# --------------------------------------------------------------------------- #
# Library fingerprinting (gap #8) — don't re-flag audited library code across
# hundreds of contracts. Detectors/coverage can skip these paths.
# --------------------------------------------------------------------------- #
_KNOWN_LIBRARY_MARKERS = (
    "@openzeppelin/", "openzeppelin/contracts", "solmate/", "solady/",
    "@uniswap/", "@chainlink/", "forge-std/", "ds-test/", "@layerzerolabs/",
    "lib/openzeppelin", "lib/solmate", "lib/solady", "lib/forge-std",
)


def is_known_library_file(path: str) -> bool:
    p = (path or "").replace("\\", "/").lower()
    return any(mk in p for mk in _KNOWN_LIBRARY_MARKERS)


def project_source_files(source_files: dict[str, str]) -> dict[str, str]:
    """Source files with audited 3rd-party libraries stripped out (best effort).

    Keeps the result non-empty: if everything looks like a library, return the
    original (better to over-scan than to scan nothing)."""
    project = {p: c for p, c in source_files.items() if not is_known_library_file(p)}
    return project or source_files


def write_source_to_workspace(source_dir: Path, pkg: SourcePackage) -> Path:
    """Write all source files (and raw payload) under ``source_dir``."""
    source_dir.mkdir(parents=True, exist_ok=True)

    # Always persist the raw payload for auditability.
    (source_dir / "_raw_sourcecode.txt").write_text(
        pkg.raw_source_code or "", encoding="utf-8", errors="replace"
    )
    if pkg.abi is not None:
        (source_dir / "abi.json").write_text(
            json.dumps(pkg.abi, indent=2), encoding="utf-8"
        )
    meta = {
        "address": pkg.address,
        "verified": pkg.verified,
        "contract_name": pkg.contract_name,
        "compiler_version": pkg.compiler_version,
        "solc_version": pkg.solc_version,
        "evm_version": pkg.evm_version,
        "optimization_used": pkg.optimization_used,
        "optimization_runs": pkg.optimization_runs,
        "is_proxy_per_explorer": pkg.is_proxy,
        "implementation_per_explorer": pkg.implementation,
        "error": pkg.error,
    }
    (source_dir / "_meta.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")

    for relpath, content in pkg.source_files.items():
        fpath = source_dir / relpath
        fpath.parent.mkdir(parents=True, exist_ok=True)
        fpath.write_text(content or "", encoding="utf-8", errors="replace")

    return source_dir
