"""Portable signed coordination records and deterministic offline verification."""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from enum import StrEnum
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey


def canonical(value: Any) -> bytes:
    """Deterministic JSON subset (sorted keys, UTF-8, no floats); RFC 8785 is not claimed."""

    def reject_floats(item: Any) -> None:
        if isinstance(item, float):
            raise ValueError("floating point values are not allowed in canonical records")
        if isinstance(item, dict):
            for child in item.values():
                reject_floats(child)
        elif isinstance(item, (list, tuple)):
            for child in item:
                reject_floats(child)

    reject_floats(value)
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def digest(value: Any) -> str:
    return hashlib.sha256(canonical(value)).hexdigest()


class Verdict(StrEnum):
    VERIFIED = "VERIFIED"
    VIOLATION = "VIOLATION"
    ABSTAIN = "ABSTAIN"


@dataclass(frozen=True)
class Task:
    task_id: str
    agent: str
    contract_digest: str
    dependencies: tuple[str, ...] = ()
    required_artifact: bool = True


@dataclass(frozen=True)
class Contract:
    workflow_id: str
    version: int
    root_intent_digest: str
    participants: tuple[str, ...]
    tasks: tuple[Task, ...]
    budget: int = 100
    witness_quorum: int = 2
    witness_count: int = 3
    allow_retry: bool = False

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class Event:
    event_id: str
    event_type: str
    workflow_id: str
    task_id: str | None
    actor_id: str
    actor_sequence: int
    previous_actor_event_hash: str | None
    causal_parent_event_ids: tuple[str, ...]
    contract_digest: str
    issued_at: str
    idempotency_key: str | None
    payload: dict[str, Any]
    signature: str

    def unsigned(self) -> dict[str, Any]:
        data = asdict(self)
        data.pop("signature")
        return data

    @property
    def event_hash(self) -> str:
        return digest({**self.unsigned(), "signature": self.signature})


@dataclass(frozen=True)
class Finding:
    rule_id: str
    category: str
    status: Verdict
    description: str
    evidence_refs: tuple[str, ...] = ()


@dataclass
class AuditBundle:
    contract: dict[str, Any]
    events: list[dict[str, Any]]
    public_keys: dict[str, str]
    witness_receipts: list[dict[str, str]] = field(default_factory=list)
    missing_evidence: bool = False
    partitioned: bool = False
    previous_checkpoint_size: int | None = None
    checkpoint_size: int | None = None
    merkle_root: str | None = None
    inclusion_proofs: dict[str, list[str]] = field(default_factory=dict)


def public_key_bytes(key: Ed25519PublicKey) -> str:
    from cryptography.hazmat.primitives import serialization

    return key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()


def sign_event(
    *,
    key: Ed25519PrivateKey,
    event_id: str,
    event_type: str,
    workflow_id: str,
    task_id: str | None,
    actor_id: str,
    sequence: int,
    previous_hash: str | None,
    parents: tuple[str, ...],
    contract_digest: str,
    payload: dict[str, Any],
    idempotency_key: str | None = None,
) -> Event:
    unsigned = {
        "event_id": event_id,
        "event_type": event_type,
        "workflow_id": workflow_id,
        "task_id": task_id,
        "actor_id": actor_id,
        "actor_sequence": sequence,
        "previous_actor_event_hash": previous_hash,
        "causal_parent_event_ids": parents,
        "contract_digest": contract_digest,
        "issued_at": "2026-01-01T00:00:00Z",
        "idempotency_key": idempotency_key,
        "payload": payload,
    }
    signature = key.sign(canonical(unsigned)).hex()
    return Event(
        event_id=event_id,
        event_type=event_type,
        workflow_id=workflow_id,
        task_id=task_id,
        actor_id=actor_id,
        actor_sequence=sequence,
        previous_actor_event_hash=previous_hash,
        causal_parent_event_ids=parents,
        contract_digest=contract_digest,
        issued_at="2026-01-01T00:00:00Z",
        idempotency_key=idempotency_key,
        payload=payload,
        signature=signature,
    )


def verify_bundle(bundle: AuditBundle) -> tuple[Verdict, list[Finding]]:
    """Verify signatures, per-actor chains, DAG dependencies, policy conflicts and evidence."""
    findings: list[Finding] = []
    try:
        contract = bundle.contract
        tasks = {t["task_id"]: t for t in contract["tasks"]}
        events = [Event(**e) for e in bundle.events]
        contract_hash = digest(contract)
    except (KeyError, TypeError, ValueError) as exc:
        return Verdict.ABSTAIN, [
            Finding(
                "ACI-SCHEMA-001",
                "integrity",
                Verdict.ABSTAIN,
                f"Malformed or unsupported bundle: {exc}",
            )
        ]

    by_id: dict[str, Event] = {}
    actor_heads: dict[str, tuple[int, str]] = {}
    for event in events:
        if event.event_id in by_id:
            findings.append(
                Finding(
                    "ACI-EVENT-DUPLICATE-001",
                    "integrity",
                    Verdict.VIOLATION,
                    "Duplicate event identifier.",
                    (event.event_id,),
                )
            )
            continue
        by_id[event.event_id] = event
        if event.workflow_id != contract["workflow_id"] or event.contract_digest != contract_hash:
            findings.append(
                Finding(
                    "ACI-CONTRACT-DRIFT-001",
                    "coordination",
                    Verdict.VIOLATION,
                    "Event references a different workflow or contract.",
                    (event.event_id,),
                )
            )
        key_hex = bundle.public_keys.get(event.actor_id)
        if key_hex is None:
            findings.append(
                Finding(
                    "ACI-KEY-UNKNOWN-001",
                    "integrity",
                    Verdict.ABSTAIN,
                    "Signing key is not in the supplied trust store.",
                    (event.event_id,),
                )
            )
        else:
            try:
                Ed25519PublicKey.from_public_bytes(bytes.fromhex(key_hex)).verify(
                    bytes.fromhex(event.signature), canonical(event.unsigned())
                )
            except (InvalidSignature, ValueError):
                findings.append(
                    Finding(
                        "ACI-SIGNATURE-001",
                        "integrity",
                        Verdict.VIOLATION,
                        "Event signature is invalid.",
                        (event.event_id,),
                    )
                )
        expected = actor_heads.get(event.actor_id)
        if expected is not None and (
            event.actor_sequence != expected[0] + 1
            or event.previous_actor_event_hash != expected[1]
        ):
            findings.append(
                Finding(
                    "ACI-CHAIN-001",
                    "integrity",
                    Verdict.VIOLATION,
                    "Participant-local event chain is discontinuous.",
                    (event.event_id,),
                )
            )
        actor_heads[event.actor_id] = (event.actor_sequence, event.event_hash)

    if bundle.merkle_root is not None:
        from aci.transparency import verify_inclusion

        try:
            tree_root = bytes.fromhex(bundle.merkle_root)
            for index, event in enumerate(events):
                proof = [bytes.fromhex(value) for value in bundle.inclusion_proofs[event.event_id]]
                if not verify_inclusion(
                    event.event_hash.encode(), index, len(events), proof, tree_root
                ):
                    findings.append(
                        Finding(
                            "ACI-MERKLE-INCLUSION-001",
                            "integrity",
                            Verdict.VIOLATION,
                            "Event does not match its transparency inclusion proof.",
                            (event.event_id,),
                        )
                    )
        except (KeyError, ValueError):
            findings.append(
                Finding(
                    "ACI-MERKLE-INCLUSION-001",
                    "integrity",
                    Verdict.ABSTAIN,
                    "Transparency inclusion evidence is malformed or incomplete.",
                )
            )
    else:
        findings.append(
            Finding(
                "ACI-MERKLE-MISSING-001",
                "integrity",
                Verdict.ABSTAIN,
                "Bundle has no transparency root and inclusion proofs.",
            )
        )

    completed: set[str] = set()
    accepted: dict[str, str] = {}
    idempotency: dict[str, str] = {}
    reservations: list[Event] = []
    commitments: dict[str, set[str]] = {}
    allowed = {
        "workflow.created",
        "task.proposed",
        "task.accepted",
        "task.started",
        "delegation.granted",
        "delegation.revoked",
        "resource.reserved",
        "resource.released",
        "artifact.committed",
        "task.completed",
        "task.verified",
        "task.failed",
        "task.disputed",
        "checkpoint.witnessed",
        "task.retry",
    }
    for event in events:
        if event.event_type not in allowed:
            findings.append(
                Finding(
                    "ACI-EVENT-TYPE-001",
                    "integrity",
                    Verdict.VIOLATION,
                    "Unsupported event type.",
                    (event.event_id,),
                )
            )
        missing_parents = [p for p in event.causal_parent_event_ids if p not in by_id]
        if missing_parents:
            findings.append(
                Finding(
                    "ACI-CAUSAL-PARENT-001",
                    "coordination",
                    Verdict.ABSTAIN,
                    "Causal parent is absent from this bundle.",
                    (event.event_id,),
                )
            )
        if event.event_type in {"task.proposed", "task.accepted"} and event.task_id:
            commitments.setdefault(event.task_id, set()).add(
                event.payload.get("contract_digest", "")
            )
        if event.event_type == "task.accepted" and event.task_id:
            accepted[event.task_id] = event.payload.get("contract_digest", "")
            if event.actor_id != tasks.get(event.task_id, {}).get("agent"):
                findings.append(
                    Finding(
                        "ACI-AUTHORITY-001",
                        "authority",
                        Verdict.VIOLATION,
                        "Task acceptance actor is not the assigned participant.",
                        (event.event_id,),
                    )
                )
        if event.event_type in {"task.started", "task.completed"} and event.task_id:
            task = tasks.get(event.task_id)
            if task is None:
                findings.append(
                    Finding(
                        "ACI-TASK-UNKNOWN-001",
                        "coordination",
                        Verdict.VIOLATION,
                        "Event references an undeclared task.",
                        (event.event_id,),
                    )
                )
                continue
            if event.actor_id != task["agent"]:
                findings.append(
                    Finding(
                        "ACI-AUTHORITY-001",
                        "authority",
                        Verdict.VIOLATION,
                        "Action actor is outside the assigned task authority.",
                        (event.event_id,),
                    )
                )
            if event.task_id not in accepted:
                findings.append(
                    Finding(
                        "ACI-STATE-001",
                        "coordination",
                        Verdict.VIOLATION,
                        "Task execution occurred before acceptance.",
                        (event.event_id,),
                    )
                )
            unmet = set(task.get("dependencies", [])) - completed
            if unmet and event.event_type == "task.started":
                findings.append(
                    Finding(
                        "ACI-DEPENDENCY-001",
                        "coordination",
                        Verdict.VIOLATION,
                        f"Task started before dependencies completed: {sorted(unmet)}.",
                        (event.event_id,),
                    )
                )
            if event.event_type == "task.completed":
                if event.payload.get("contract_digest") != accepted[event.task_id]:
                    findings.append(
                        Finding(
                            "ACI-CONTRACT-DRIFT-001",
                            "coordination",
                            Verdict.VIOLATION,
                            "Completion changed the accepted task contract.",
                            (event.event_id,),
                        )
                    )
                elif event.payload.get("artifact_digest"):
                    completed.add(event.task_id)
                elif task.get("required_artifact", True):
                    findings.append(
                        Finding(
                            "ACI-ARTIFACT-MISSING-001",
                            "outcome",
                            Verdict.ABSTAIN,
                            "Required artifact commitment is absent.",
                            (event.event_id,),
                        )
                    )
        if event.event_type == "resource.reserved":
            reservations.append(event)
        if event.event_type == "delegation.granted":
            allowed_actions = set(
                contract.get("delegation_policy", {}).get(
                    "allowed_actions", ["read", "compute", "write"]
                )
            )
            requested = set(event.payload.get("action_scope", []))
            if not requested.issubset(allowed_actions):
                findings.append(
                    Finding(
                        "ACI-DELEGATION-SCOPE-001",
                        "authority",
                        Verdict.VIOLATION,
                        "Delegation exceeds the workflow action scope.",
                        (event.event_id,),
                    )
                )
        if event.idempotency_key:
            if event.idempotency_key in idempotency:
                findings.append(
                    Finding(
                        "ACI-REPLAY-001",
                        "coordination",
                        Verdict.VIOLATION,
                        "Consequential idempotency key was reused.",
                        (idempotency[event.idempotency_key], event.event_id),
                    )
                )
            idempotency[event.idempotency_key] = event.event_id
        if event.event_type == "task.retry" and not contract.get("allow_retry", False):
            findings.append(
                Finding(
                    "ACI-RETRY-001",
                    "coordination",
                    Verdict.VIOLATION,
                    "Retry is not permitted by the contract.",
                    (event.event_id,),
                )
            )

    for task_id, values in commitments.items():
        if len(values) > 1:
            findings.append(
                Finding(
                    "ACI-EQUIVOCATION-001",
                    "coordination",
                    Verdict.VIOLATION,
                    "Conflicting signed commitments exist for one exclusive task.",
                    tuple(e.event_id for e in events if e.task_id == task_id),
                )
            )
    capacity = contract.get("budget", 0)
    total = sum(int(e.payload.get("amount", 0)) for e in reservations)
    if total > capacity:
        findings.append(
            Finding(
                "ACI-RESOURCE-001",
                "coordination",
                Verdict.VIOLATION,
                f"Evidenced reservations ({total}) exceed budget ({capacity}).",
                tuple(e.event_id for e in reservations),
            )
        )
    if bundle.checkpoint_size is not None and bundle.previous_checkpoint_size is not None:
        if bundle.checkpoint_size < bundle.previous_checkpoint_size:
            findings.append(
                Finding(
                    "ACI-CHECKPOINT-ROLLBACK-001",
                    "integrity",
                    Verdict.VIOLATION,
                    "Checkpoint is older than a previously witnessed checkpoint.",
                )
            )
    if len(bundle.witness_receipts) < contract.get("witness_quorum", 0):
        findings.append(
            Finding(
                "ACI-WITNESS-QUORUM-001",
                "integrity",
                Verdict.ABSTAIN,
                "Required independent witness quorum is unavailable.",
            )
        )
    if bundle.partitioned:
        findings.append(
            Finding(
                "ACI-PARTITION-001",
                "coordination",
                Verdict.ABSTAIN,
                "Common commit state could not be established during partition.",
            )
        )
    if bundle.missing_evidence:
        findings.append(
            Finding(
                "ACI-OUTCOME-001",
                "outcome",
                Verdict.ABSTAIN,
                "Required workflow evidence is unavailable.",
            )
        )
    if not findings:
        findings.append(
            Finding(
                "ACI-VERIFIED-001",
                "outcome",
                Verdict.VERIFIED,
                "All configured checks passed for the supplied evidence.",
            )
        )
    verdict = (
        Verdict.VIOLATION
        if any(f.status == Verdict.VIOLATION for f in findings)
        else Verdict.ABSTAIN
        if any(f.status == Verdict.ABSTAIN for f in findings)
        else Verdict.VERIFIED
    )
    return verdict, findings
