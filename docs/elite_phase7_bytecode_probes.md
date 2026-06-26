# Elite Phase 7: Bytecode Selector Probes

Phase 7 builds on the Phase 6 bytecode-intel lane. When bytecode-intel finds a
high-signal runtime cluster, Phase 7 generates the next validation step:
selector-specific probe plans, read-only `cast call` commands, and a Foundry
fork harness.

## What It Adds

- New `bytecode-probes` tool run, enabled by default with
  `ENABLE_BYTECODE_PROBES=true`.
- `probe_plan.json` for each target with bytecode risk signals.
- `BYTECODE_PROBES.md` with operator commands.
- `foundry/test/BytecodeSelectorProbes.t.sol` with fork-only selector probes.
- `bytecode_periphery` findings now include probe artifact paths and suggested
  selector calls.

## Safety Model

The generated commands are intended for local forks and read-only calls only.
They never broadcast transactions and they do not include private keys.

Use the harness to answer:

- Does a privileged selector reject an unprivileged caller?
- Does an arbitrary executor selector accept caller-controlled target/calldata?
- Does an approval-spender selector expose victim/receiver/amount control?
- Does a bytecode-only proxy/clone need implementation-level follow-up?

## Artifact Paths

```text
backend/outputs/scans/<scan_id>/<target>/tools/bytecode-probes/
  probe_plan.json
  BYTECODE_PROBES.md
  foundry/foundry.toml
  foundry/test/BytecodeSelectorProbes.t.sol
```

## Example

```bash
cd backend/outputs/scans/<scan_id>/<target>/tools/bytecode-probes/foundry
RPC_URL=$RPC_URL forge test -vv
```

## Next Plan

After Phase 7, the strongest next step is not another detector phase. It is a
large regression campaign: run Ultra Deep V2 against already exploited
contracts, record expected detector/probe hits, and turn every miss into a new
benchmark case or detector patch.
