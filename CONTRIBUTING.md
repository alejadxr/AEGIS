# Contributing to AEGIS

We welcome contributions! See our [GitHub Issues](../../issues) for open tasks.

## Quick Start
1. Fork and clone
2. `cd backend && pip install -r requirements.txt && pytest tests/ -v`
3. `cd frontend && npm install && npm run build`
4. Create a branch, make changes, open a PR

## Code Style
- Python: PEP 8, type hints, async/await
- TypeScript: strict mode, Tailwind
- Rust: `cargo fmt`
- Commits: [Conventional Commits](https://www.conventionalcommits.org/)

## Pre-commit guard
Enable it with `git config core.hooksPath scripts/git-hooks`. To keep your own private infrastructure identifiers (IPs, hostnames, emails) out of commits, list them one per line (regex or literal, `#` comments) in an untracked `~/.aegis-private-patterns` file (`chmod 600`); the hook blocks any staged file matching them. If the file is missing it is skipped.

## License
Contributions are licensed under AGPL-3.0.
