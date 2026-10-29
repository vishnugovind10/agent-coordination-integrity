"""Deterministic synthetic scenarios for the CLI and adversarial tests."""

from __future__ import annotations

from dataclasses import asdict
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from aci.core import AuditBundle, Contract, Task, digest, public_key_bytes, sign_event
from aci.transparency import inclusion_proof, root_hash


def build_scenario(name: str) -> AuditBundle:
    if name not in {
        "clean",
        "contract-drift",
        "delegation-escalation",
        "equivocation",
        "replay",
        "duplicate-side-effect",
        "missing-evidence",
        "rollback",
        "resource-overallocation",
        "concurrency",
        "partition",
        "retry",
    }:
        raise ValueError(f"unknown scenario: {name}")
    keys = {
        actor: Ed25519PrivateKey.from_private_bytes(bytes([i]) * 32)
        for i, actor in enumerate(("coordinator", "researcher", "analyst", "reviewer"), 1)
    }
    task_defs = (
        Task("research", "researcher", digest({"task": "research", "criteria": "sources"})),
        Task(
            "analysis",
            "analyst",
            digest({"task": "analysis", "criteria": "calculate"}),
            dependencies=("research",),
        ),
    )
    contract = Contract(
        "wf-demo-001",
        1,
        digest({"intent": "synthetic research"}),
        tuple(keys),
        task_defs,
        allow_retry=name == "retry",
    )
    cdict = contract.to_dict()
    cdict["delegation_policy"] = {"allowed_actions": ["read", "compute", "write"]}
    chash = digest(cdict)
    events: list[dict[str, Any]] = []
    seq: dict[str, int] = {}
    previous: dict[str, str] = {}

    def emit(
        actor: str,
        kind: str,
        task_id: str | None = None,
        payload: dict[str, Any] | None = None,
        parents: tuple[str, ...] = (),
        idempotency: str | None = None,
    ) -> str:
        seq[actor] = seq.get(actor, 0) + 1
        event = sign_event(
            key=keys[actor],
            event_id=f"evt-{len(events) + 1:03}",
            event_type=kind,
            workflow_id=contract.workflow_id,
            task_id=task_id,
            actor_id=actor,
            sequence=seq[actor],
            previous_hash=previous.get(actor),
            parents=parents,
            contract_digest=chash,
            payload=payload or {},
            idempotency_key=idempotency,
        )
        events.append(asdict(event))
        previous[actor] = event.event_hash
        return event.event_id

    root = emit("coordinator", "workflow.created", payload={"contract_digest": chash})
    for task in task_defs:
        changed = digest({"task": task.task_id, "criteria": "changed"})
        assignment = (
            changed
            if name == "equivocation" and task.task_id == "research"
            else task.contract_digest
        )
        emit("coordinator", "task.proposed", task.task_id, {"contract_digest": assignment}, (root,))
        emit(
            task.agent,
            "task.accepted",
            task.task_id,
            {"contract_digest": task.contract_digest},
            (root,),
        )
        if name == "equivocation" and task.task_id == "research":
            emit(
                "coordinator", "task.proposed", task.task_id, {"contract_digest": changed}, (root,)
            )

    prior_task_events: dict[str, str] = {}
    for task in task_defs:
        parents = (prior_task_events[task.dependencies[0]],) if task.dependencies else (root,)
        emit(task.agent, "task.started", task.task_id, {}, parents)
        if name == "contract-drift" and task.task_id == "research":
            actual_contract = digest({"changed": True})
        else:
            actual_contract = task.contract_digest
        if name == "delegation-escalation" and task.task_id == "research":
            emit(
                "researcher",
                "delegation.granted",
                task.task_id,
                {"delegate": "analyst", "action_scope": ["admin"]},
                parents,
            )
        if name == "resource-overallocation":
            emit(task.agent, "resource.reserved", task.task_id, {"amount": 60}, parents)
        if name in {"replay", "duplicate-side-effect"}:
            emit(
                task.agent,
                "artifact.committed",
                task.task_id,
                {"artifact_digest": digest({"task": task.task_id})},
                parents,
                "same-action",
            )
        artifact = (
            ""
            if name == "missing-evidence" and task.task_id == "analysis"
            else digest({"task": task.task_id})
        )
        complete = emit(
            task.agent,
            "task.completed",
            task.task_id,
            {"contract_digest": actual_contract, "artifact_digest": artifact},
            parents,
        )
        prior_task_events[task.task_id] = complete
    if name == "retry":
        emit(
            "analyst",
            "task.retry",
            "analysis",
            {"attempt": 2},
            (prior_task_events["analysis"],),
            "analysis-retry",
        )
    if name == "rollback":
        old_size, current_size = 3, 2
    else:
        old_size, current_size = None, None
    leaf_data = [_event_hash(event).encode() for event in events]
    tree_root = root_hash(leaf_data).hex()
    proofs = {
        event["event_id"]: [part.hex() for part in inclusion_proof(leaf_data, i)]
        for i, event in enumerate(events)
    }
    return AuditBundle(
        contract=cdict,
        events=events,
        public_keys={actor: public_key_bytes(key.public_key()) for actor, key in keys.items()},
        witness_receipts=[
            {"witness_id": "witness-a", "checkpoint_hash": "synthetic"},
            {"witness_id": "witness-b", "checkpoint_hash": "synthetic"},
        ],
        missing_evidence=name == "missing-evidence",
        partitioned=name == "partition",
        previous_checkpoint_size=old_size,
        checkpoint_size=current_size,
        merkle_root=tree_root,
        inclusion_proofs=proofs,
    )


def _event_hash(event: dict[str, Any]) -> str:
    from aci.core import Event

    return Event(**event).event_hash
