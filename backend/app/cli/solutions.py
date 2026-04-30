"""AEGIS CLI — solution package management subcommands.

Usage:
    python -m app.cli.solutions list
    python -m app.cli.solutions install <id>
    python -m app.cli.solutions uninstall <id>
    python -m app.cli.solutions update <id>
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from app.services.solution_manager import SolutionManager

_DEFAULT_SOLUTIONS_DIR = Path(__file__).parent.parent.parent.parent / "solutions"


def cmd_list(args: argparse.Namespace) -> int:
    manager = SolutionManager(args.solutions_dir)
    solutions = manager.discover()
    installed = set(manager.list_installed())

    if not solutions:
        print("No solutions found in:", args.solutions_dir)
        return 0

    print(f"{'ID':<30} {'VERSION':<10} {'STATUS':<12} NAME")
    print("-" * 75)
    for solution_id, sol in sorted(solutions.items()):
        status = "installed" if solution_id in installed else "available"
        print(f"{solution_id:<30} {sol.version:<10} {status:<12} {sol.name}")
    return 0


def cmd_install(args: argparse.Namespace) -> int:
    manager = SolutionManager(args.solutions_dir)
    try:
        manager.install(args.id)
        print(f"Installed: {args.id}")
        return 0
    except (KeyError, RuntimeError, FileNotFoundError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1


def cmd_uninstall(args: argparse.Namespace) -> int:
    manager = SolutionManager(args.solutions_dir)
    try:
        manager.uninstall(args.id)
        print(f"Uninstalled: {args.id}")
        return 0
    except (KeyError, RuntimeError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1


def cmd_update(args: argparse.Namespace) -> int:
    manager = SolutionManager(args.solutions_dir)
    try:
        manager.update(args.id)
        print(f"Updated: {args.id}")
        return 0
    except (KeyError, RuntimeError, FileNotFoundError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="aegis solution",
        description="AEGIS solution package manager",
    )
    parser.add_argument(
        "--solutions-dir",
        type=Path,
        default=_DEFAULT_SOLUTIONS_DIR,
        help="Path to solutions directory (default: repo root /solutions)",
    )

    sub = parser.add_subparsers(dest="command", metavar="COMMAND")
    sub.required = True

    sub.add_parser("list", help="List all discovered solutions and their install status")

    install_p = sub.add_parser("install", help="Install a solution by id")
    install_p.add_argument("id", help="Solution id (e.g. web-app-defense)")

    uninstall_p = sub.add_parser("uninstall", help="Uninstall a solution by id")
    uninstall_p.add_argument("id", help="Solution id")

    update_p = sub.add_parser("update", help="Re-install (update) a solution from local path")
    update_p.add_argument("id", help="Solution id")

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    dispatch = {
        "list": cmd_list,
        "install": cmd_install,
        "uninstall": cmd_uninstall,
        "update": cmd_update,
    }
    return dispatch[args.command](args)


if __name__ == "__main__":
    sys.exit(main())
