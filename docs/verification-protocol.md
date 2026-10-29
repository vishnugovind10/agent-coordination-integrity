# Verification protocol (prototype)

1. Parse the bundle and contract. Unsupported or malformed data produces `ABSTAIN`.
2. Recompute the contract digest, validate event signatures, and check per-actor sequence/hash references.
3. Check assignment and declared delegation action scope.
4. Check event vocabulary, contract references, task acceptance, dependencies, duplicate idempotency keys, exclusive-task commitments, reservations, witness quorum availability, checkpoint size and declared outcome evidence.
5. Apply precedence: any demonstrated violation -> `VIOLATION`; otherwise unresolved required evidence -> `ABSTAIN`; otherwise `VERIFIED`.

Events use SHA-256 over sorted-key compact UTF-8 JSON and Ed25519 from `cryptography`. The encoding excludes floating point values. It is deliberately documented as a deterministic subset and not a claim of RFC 8785 conformance. Inclusion proofs use RFC 9162-style leaf/node domain separation and recursive tree splitting. Tree consistency proofs, persistent append-only storage, and authenticated witness receipts are not implemented.
