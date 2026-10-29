"""Command-line entry points."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Annotated

import typer

from aci.core import AuditBundle, verify_bundle
from aci.simulation import build_scenario

app = typer.Typer(no_args_is_help=True, help="Independent multi-agent coordination verifier")


def report(bundle: AuditBundle) -> dict[str, object]:
    verdict, findings = verify_bundle(bundle)
    return {
        "schema_version": "1.0",
        "workflow_id": bundle.contract.get("workflow_id"),
        "verdict": verdict.value,
        "findings": [
            {
                "rule_id": f.rule_id,
                "category": f.category,
                "status": f.status.value,
                "description": f.description,
                "evidence_refs": f.evidence_refs,
            }
            for f in findings
        ],
    }


@app.command()
def demo(scenario: Annotated[str, typer.Option()] = "clean") -> None:
    """Run a deterministic synthetic attack or clean workflow."""
    try:
        result = report(build_scenario(scenario))
    except ValueError as exc:
        raise typer.BadParameter(str(exc)) from exc
    typer.echo(json.dumps(result, indent=2))


@app.command()
def verify(bundle_path: Annotated[Path, typer.Argument(exists=True, dir_okay=False)]) -> None:
    """Verify an exported audit bundle offline."""
    try:
        bundle = AuditBundle(**json.loads(bundle_path.read_text(encoding="utf-8")))
    except (json.JSONDecodeError, TypeError) as exc:
        raise typer.BadParameter(f"invalid audit bundle: {exc}") from exc
    result = report(bundle)
    typer.echo(json.dumps(result, indent=2))
    if result["verdict"] != "VERIFIED":
        raise typer.Exit(code=1)


@app.command()
def export(
    scenario: Annotated[str, typer.Option()] = "clean",
    output: Annotated[Path, typer.Option()] = Path("audit-bundle.json"),
) -> None:
    """Export a self-contained public-key audit bundle."""
    bundle = build_scenario(scenario)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(bundle.__dict__, indent=2), encoding="utf-8")
    typer.echo(str(output))
