# Architecture

The portable bundle contains a versioned workflow contract, signed participant events, public keys, and witness receipt references. The verifier reconstructs the declared workflow context without opening the coordinator's database.

```text
participants -> signed commitments/events -> portable bundle -> independent verifier
                                                  |-> authority scope
                                                  |-> signature and chain integrity
                                                  |-> causal/task consistency
                                                  |-> outcome evidence
```

The core has four distinct questions: authority, integrity, coordination consistency, and outcome evidence. The coordinator may route and aggregate but is not the verifier's source of truth. This version implements a bounded set of checks and a deterministic local fixture. It does not provide distributed storage, a production witness network, or consensus.

The authority boundary is an adapter seam. A future provider can supply AgencyOS decisions; this project does not recreate identity, passports, exposure controls, or financial consequence assurance.
