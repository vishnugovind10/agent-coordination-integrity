from __future__ import annotations

import pytest
from hypothesis import given
from hypothesis import strategies as st

from aci.core import Verdict, verify_bundle
from aci.simulation import build_scenario


@pytest.mark.parametrize(
    ("scenario", "expected"),
    [
        ("clean", Verdict.VERIFIED),
        ("contract-drift", Verdict.VIOLATION),
        ("delegation-escalation", Verdict.VIOLATION),
        ("equivocation", Verdict.VIOLATION),
        ("replay", Verdict.VIOLATION),
        ("duplicate-side-effect", Verdict.VIOLATION),
        ("missing-evidence", Verdict.ABSTAIN),
        ("rollback", Verdict.VIOLATION),
        ("resource-overallocation", Verdict.VIOLATION),
        ("concurrency", Verdict.VERIFIED),
        ("partition", Verdict.ABSTAIN),
        ("retry", Verdict.VERIFIED),
    ],
)
def test_scenario_verdicts(scenario: str, expected: Verdict) -> None:
    assert verify_bundle(build_scenario(scenario))[0] == expected


@given(st.dictionaries(st.text(min_size=1), st.integers(), max_size=20))
def test_canonical_digest_is_key_order_independent(record: dict[str, int]) -> None:
    from aci.core import digest

    assert digest(record) == digest(dict(reversed(list(record.items()))))


def test_tampered_payload_is_detected() -> None:
    bundle = build_scenario("clean")
    bundle.events[0]["payload"]["forged"] = True
    verdict, findings = verify_bundle(bundle)
    assert verdict == Verdict.VIOLATION
    assert any(f.rule_id == "ACI-SIGNATURE-001" for f in findings)


@pytest.mark.parametrize("size", range(1, 18))
def test_merkle_inclusion_proofs_cover_uneven_tree_sizes(size: int) -> None:
    from aci.transparency import inclusion_proof, root_hash, verify_inclusion

    leaves = [f"event-{i}".encode() for i in range(size)]
    root = root_hash(leaves)
    for index, leaf in enumerate(leaves):
        proof = inclusion_proof(leaves, index)
        assert verify_inclusion(leaf, index, size, proof, root)
        assert not verify_inclusion(leaf + b"-changed", index, size, proof, root)
