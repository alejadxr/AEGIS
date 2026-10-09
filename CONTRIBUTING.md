# Contributing to AEGIS

We welcome contributions! See our [GitHub Issues](../../issues) for open tasks.

## Quick Start
1. Fork and clone, then run `git config core.hooksPath scripts/git-hooks` once in the new clone (see [Pre-commit guard](#pre-commit-guard); hooks are local config and are not cloned)
2. `cd backend && pip install -r requirements.txt && pytest tests/ -v`
3. `cd frontend && npm install && npm run build`
4. Create a branch, make changes, open a PR

## Code Style
- Python: PEP 8, type hints, async/await
- TypeScript: strict mode, Tailwind
- Rust: `cargo fmt`
- Commits: [Conventional Commits](https://www.conventionalcommits.org/)

## Pre-commit guard
This repo is public, so commits are checked for private files and infrastructure identifiers.

**Every fresh clone must run `git config core.hooksPath scripts/git-hooks`.** `core.hooksPath` is local git config: it is never cloned, so a new clone has no hook until you set it.

The hook refuses, by file name and regardless of content, `CLAUDE.md`, `AGENTS.md`, `MEMORY.md`, `GEMINI.md`, anything under `.claude/`, `.claude.json` and real `.env` / `.env.*` files (`*.example` templates are fine), even if you `git add -f` them. It also blocks credentials and infrastructure shapes in file content (home paths like `/Users/<name>/`, Tailscale-range `100.64.0.0/10` addresses, non-default `192.168.x.y` LANs); use placeholders such as `/Users/example/`, `100.64.0.x` or `203.0.113.x`.

To keep your own private identifiers (IPs, hostnames, usernames, ISP names) out of commits, list them one per line (regex or literal, `#` comments) in an untracked `~/.aegis-private-patterns` file (`chmod 600`); the hook blocks any staged file matching them. If the file is missing it is skipped.

CI re-runs the same checks on the tracked tree (`scripts/git-hooks/pre-commit --tracked`, which you can also run locally), so `--no-verify` or a clone without the hook still fails the build.

## License
Contributions are licensed under AGPL-3.0.
