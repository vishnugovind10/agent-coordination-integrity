# Attack catalog

| Scenario | Expected | Rule or meaning |
|---|---|---|
| Clean | VERIFIED | Signed synthetic workflow with required artifacts |
| Contract drift | VIOLATION | Completion contract differs from accepted commitment |
| Delegation escalation | VIOLATION | Requested action exceeds workflow scope |
| Coordinator equivocation | VIOLATION | Conflicting exclusive-task commitments both evidenced |
| Replay / duplicate side effect | VIOLATION | Idempotency key reused |
| Missing evidence | ABSTAIN | Required output commitment unavailable |
| Checkpoint rollback | VIOLATION | Presented size is below previously witnessed size |
| Resource over-allocation | VIOLATION | Evidenced reservation total exceeds budget |
| Legitimate concurrency | VERIFIED | Independent causal branches remain permitted |
| Partition | ABSTAIN | Required common commit cannot be established |
| Valid retry | VERIFIED | Retry explicitly permitted by contract |

These are executable fixtures in `tests/test_verifier.py`; they do not establish production coverage.
