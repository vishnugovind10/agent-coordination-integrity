# Limitations

This version is a small offline reference implementation, not a production security control. Its demo keys and witness receipts are synthetic. It implements bundle-local Merkle inclusion proofs with RFC 9162-style construction, but not consistency proofs, authenticated witness identities, a durable append-only event store, transitive delegation proofs, clock-skew handling, revocation, resource release replay, or full state-machine validation. It detects only the listed cases when relevant evidence is included.

The restricted canonical JSON function is not a standards-conformant RFC 8785 implementation. Do not use its signatures as an interoperability format. A production deployment would need a reviewed protocol specification, independent implementation review, key management, completeness guarantees, and actual independent witnesses.

A2A, MCP, and OpenTelemetry adapters are explicitly future integration work. A2A/MCP describe protocol/tool interactions; OpenTelemetry helps correlate operations. None alone proves a complete or untampered history.
