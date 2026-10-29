# Threat model

## Threat actors

Malicious coordinator, compromised or malicious participant, overreaching delegate, stolen signing key, malicious tool provider, network attacker, privileged database administrator, and colluding authorized agents.

## Protected properties

Event integrity and attribution, task commitment consistency, basic participant-chain continuity, declared task dependency ordering, configured delegation action scope, idempotency-key reuse detection, resource budget limits, and explicit incomplete-evidence outcomes.

## Assumptions and limits

The verifier receives an authentic trust store and a complete enough bundle. Ed25519 private keys remain secret. The demo keys are intentionally deterministic and public. Timestamp freshness, key lifecycle, revocation evidence, complete transitive delegation, and artifact content retrieval are not implemented. Causal references are checked for presence; they are not a full distributed graph proof. Witness receipts are counted but not cryptographically authenticated. The Merkle transparency design is future work.

The system does not prove truthfulness, reasoning correctness, absence of collusion, absolute security or availability, policy fairness, external-world facts, or impossibility of compromise. Valid signatures do not prevent equivocation; conflicting commitments are detectable only once both are available to a verifier or participant.
