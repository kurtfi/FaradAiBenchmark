#!/usr/bin/env python3
"""
scripts/manage_experiments.py — CLI Experiment Template Manager (ADR 0010, SPEC Phase 7)

Utility to list, export, and import declarative benchmark matrix templates
between DuckDB and Git-versionable YAML files.
"""

import argparse
import sys
from pathlib import Path
from typing import Any
import yaml

# Add repo root to path
REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from adapters.experiment_registry import (
    DEFAULT_DB_PATH,
    ExperimentTemplate,
    delete_template,
    get_template,
    init_experiment_registry,
    list_templates,
    save_template,
)


def export_template_to_yaml(template: ExperimentTemplate, out_path: Path | None = None) -> str:
    """Serialize an ExperimentTemplate to formatted YAML and optionally write to file."""
    data: dict[str, Any] = {
        "template_id": template.template_id,
        "name": template.name,
        "description": template.description or "",
        "dataset_path": template.dataset_path,
        "limit_cases": template.limit_cases,
        "models_config": template.models_config,
    }
    yaml_str = yaml.dump(data, sort_keys=False, allow_unicode=True, indent=2)

    if out_path:
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(yaml_str, encoding="utf-8")
        print(f"✓ Exported template '{template.template_id}' to: {out_path}")
    return yaml_str


def import_template_from_yaml(
    yaml_path: Path,
    db_path: Path = DEFAULT_DB_PATH,
) -> ExperimentTemplate:
    """Parse and validate YAML template file and persist into DuckDB."""
    if not yaml_path.exists():
        raise FileNotFoundError(f"Template YAML file not found: {yaml_path}")

    content = yaml_path.read_text(encoding="utf-8")
    data = yaml.safe_load(content)

    if not isinstance(data, dict):
        raise ValueError("Invalid YAML: Root structure must be a dictionary")

    required_fields = ["template_id", "name", "dataset_path", "models_config"]
    missing = [f for f in required_fields if f not in data or not data[f]]
    if missing:
        raise ValueError(f"Missing required template fields: {', '.join(missing)}")

    if not isinstance(data["models_config"], list) or len(data["models_config"]) == 0:
        raise ValueError("models_config must contain a non-empty list of model configurations")

    template = ExperimentTemplate(
        template_id=str(data["template_id"]).strip(),
        name=str(data["name"]).strip(),
        description=str(data.get("description", "")).strip(),
        dataset_path=str(data["dataset_path"]).strip(),
        models_config=data["models_config"],
        limit_cases=data.get("limit_cases"),
    )

    save_template(template, db_path)
    print(f"✓ Successfully imported and registered template '{template.template_id}' into {db_path}")
    return template


def list_templates_cli(db_path: Path = DEFAULT_DB_PATH) -> None:
    """Print all registered experiment templates."""
    try:
        from rich.console import Console
        from rich.table import Table

        console = Console()
        templates = list_templates(db_path)

        table = Table(title=f"📋 Registered Experiment Matrix Templates ({len(templates)})", border_style="cyan")
        table.add_column("Template ID (Slug)", style="bold cyan")
        table.add_column("Name", style="white")
        table.add_column("Models", justify="center", style="yellow")
        table.add_column("Limit", justify="center", style="green")
        table.add_column("Dataset Path", style="dim")

        for t in templates:
            table.add_row(
                t.template_id,
                t.name,
                str(len(t.models_config)),
                str(t.limit_cases) if t.limit_cases else "All",
                t.dataset_path,
            )

        console.print(table)
    except ImportError:
        templates = list_templates(db_path)
        print(f"Registered Experiment Templates ({len(templates)}):")
        for t in templates:
            limit_str = f"Limit: {t.limit_cases}" if t.limit_cases else "Limit: All"
            print(f"  • {t.template_id} | {t.name} | Models: {len(t.models_config)} | {limit_str}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Farad Ai Benchmark: Declarative Experiment Matrix CLI Manager"
    )
    parser.add_argument(
        "--db",
        type=Path,
        default=DEFAULT_DB_PATH,
        help="Path to DuckDB benchmark database (default: data/benchmark_runs.duckdb)",
    )
    parser.add_argument(
        "--list",
        action="store_true",
        help="List all registered experiment templates in DuckDB",
    )
    parser.add_argument(
        "--export",
        type=str,
        metavar="TEMPLATE_ID",
        help="Export template by ID to YAML",
    )
    parser.add_argument(
        "--out",
        type=Path,
        metavar="OUTPUT_YAML",
        help="Output file path for --export (if omitted, outputs to stdout)",
    )
    parser.add_argument(
        "--import",
        dest="import_file",
        type=Path,
        metavar="INPUT_YAML",
        help="Import and register experiment template from YAML file",
    )
    parser.add_argument(
        "--delete",
        type=str,
        metavar="TEMPLATE_ID",
        help="Delete experiment template by ID",
    )

    args = parser.parse_args()

    # Ensure DB schema and default seed template are present
    init_experiment_registry(args.db)

    if args.list:
        list_templates_cli(args.db)
        return

    if args.export:
        template = get_template(args.export, args.db)
        if not template:
            print(f"❌ Error: Experiment template '{args.export}' not found in database.", file=sys.stderr)
            sys.exit(1)
        yaml_out = export_template_to_yaml(template, args.out)
        if not args.out:
            print(yaml_out)
        return

    if args.import_file:
        try:
            import_template_from_yaml(args.import_file, args.db)
        except Exception as e:
            print(f"❌ Import failed: {e}", file=sys.stderr)
            sys.exit(1)
        return

    if args.delete:
        if args.delete == "exp_smoke_dual_track":
            print("⚠️ Warning: Default seed template 'exp_smoke_dual_track' is protected.", file=sys.stderr)
        deleted = delete_template(args.delete, args.db)
        if deleted:
            print(f"✓ Deleted template '{args.delete}' from {args.db}")
        else:
            print(f"❌ Template '{args.delete}' not found in {args.db}", file=sys.stderr)
            sys.exit(1)
        return

    # If no flags passed, print help and list templates
    list_templates_cli(args.db)


if __name__ == "__main__":
    main()
