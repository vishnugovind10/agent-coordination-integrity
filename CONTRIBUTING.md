# Contributing

Use synthetic fixtures and keys. Keep authority, integrity, coordination consistency and outcome assurance separate. Add a regression test for every new invariant or attack scenario. Preserve `VERIFIED`, `VIOLATION`, and `ABSTAIN` semantics; missing evidence must not be represented as success. Run `python -m pytest -q`, `ruff check .`, and `mypy src/aci` before submitting changes.
