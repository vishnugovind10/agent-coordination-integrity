# Agent Coordination Integrity

Independent verification for multi-agent coordination evidence. The coordinator does not own the only copy of the story: participants sign commitments and transitions, and a separate verifier checks the exported bundle offline.

This is a deterministic reference implementation, not production security software. Fixtures and keys are synthetic. It demonstrates selected integrity, authority-scope and workflow checks; it does not implement a production transparency log or a complete distributed consensus protocol.

## Run the demo

```powershell
python -m pip install -e ".[dev]"
aci demo --scenario clean
aci demo --scenario equivocation
aci demo --scenario missing-evidence
aci export --scenario clean --output artifacts/audit-bundle.json
aci verify artifacts/audit-bundle.json
```

Expected verdicts: clean `VERIFIED`; conflicting exclusive-task commitments `VIOLATION` (`ACI-EQUIVOCATION-001`); unavailable evidence `ABSTAIN`.

```text
CLEAN: Planner -> Researcher -> Analyst -> committed artifacts -> independent verifier -> VERIFIED
ATTACK: Coordinator -> Agent A (C1) and Agent B (C2) -> verifier -> VIOLATION
MISSING: required artifact unavailable -> verifier -> ABSTAIN
```

The verifier takes only an `AuditBundle` and its public-key trust store. No coordinator database, private key, LLM, network or prompt history is needed.

## Scenarios

The test suite exercises clean workflow, contract drift, delegation escalation, equivocation, replay, duplicate side effect, missing evidence, checkpoint rollback, resource over-allocation, legitimate concurrency, partition and permitted retry. Run `python -m pytest -q`.

## Boundaries

- `VERIFIED` means the supplied evidence passed the checks implemented by this version under the supplied trust assumptions. `VIOLATION` requires a demonstrated rule failure. `ABSTAIN` means evidence or common state is insufficient.
- Ed25519 and SHA-256 use `cryptography`; canonical JSON here is a deterministic restricted JSON subset. Full RFC 8785 compatibility is not claimed.
- The Merkle inclusion tree uses RFC 9162 domain separation and tree splitting for bundle-local inclusion proofs. It does not implement consistency proofs or a persistent append-only service. Witness receipts are synthetic placeholders; quorum counting is illustrative, not cryptographic witness validation.
- Event signatures establish attribution to a key, not truthfulness, correct reasoning, lack of collusion, or external-world facts.
- Local assignment checks and scope checks are a small standalone authority provider. An AgencyOS adapter is a future integration seam, not a live integration.
- A2A, MCP and OpenTelemetry are integration points. This version has no protocol adapters; traces are correlation data, not signed proof.
- Agent Trust Probe/AgencyOS concerns authority; Agentic Financial Consequence concerns downstream consequence assurance; Coordination Fabric and Inference Coordination Fabric provide scenario inspiration. This repository does not copy or replace them.

See [architecture](docs/architecture.md), [threat model](docs/threat-model.md), [verification protocol](docs/verification-protocol.md), [attack catalog](docs/attack-catalog.md), and [limitations](docs/limitations.md).

## Development

Python 3.11+. `make install`, `make test`, `make lint`, and `make typecheck`. The CLI has no external service requirement. See [CONTRIBUTING.md](CONTRIBUTING.md).
