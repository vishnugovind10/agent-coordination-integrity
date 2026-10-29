.PHONY: install test lint typecheck demo
install:
	python -m pip install -e '.[dev]'
test:
	python -m pytest -q
lint:
	ruff check .
typecheck:
	mypy src/aci
demo:
	aci demo --scenario clean
