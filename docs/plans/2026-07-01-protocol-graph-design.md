# Protocol Graph Design

Phase 12 builds a conservative protocol graph during each scan. The graph is generated from source, ABI, semantic facts, proxy resolution, typed external-call targets, and safe read-only address getters. It creates per-target `protocol_graph.json` artifacts plus a merged scan-level graph.

The first implementation intentionally does not auto-expand scan scope. It groups roles and lists companion scan candidates so auditors can see which oracle, controller, market, vault wrapper, AMM pair, bridge, verifier, router, asset, or strategy should be audited together. A later phase can enqueue those resolved addresses with explicit scope controls.

The graph feeds detector evidence, starting with `economic_oracle_lending`, and is surfaced in the scan and target detail UI.
