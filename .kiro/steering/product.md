# Product: kiro-secops

Template repository that packages an information security and DevSecOps baseline for Kiro.

The binary installer (`kiro-secops`) deploys a security baseline to users' machines:
- **Global layer** (`~/.kiro/`): permissions, steering, skills, and a security-review agent — follows the user across all workspaces.
- **Workspace layer** (`.kiro/` in a project): event hooks (guard, review gates), scanner configs, and CI templates — committed with the project.

Key design principle: **declarative-first** — hard blocking goes into `permissions.yaml` (global, no runtime, cross-platform); steering/skills provide soft guidance; workspace hooks automate event-driven checks.

The payload lives **inert** under `internal/assets/payload/` — it does not configure this repo itself. The installer embeds it via `//go:embed` and deploys it to the target location.

## Main commands

| Command | Target | Purpose |
|---------|--------|---------|
| `kiro-secops install` | `~/.kiro/` | Deploy global baseline (1x per machine/user) |
| `kiro-secops init` | `.kiro/` of a project | Scaffold workspace hooks + scanner configs |
| `kiro-secops guard` | stdin (hook) | Evaluate tool calls against deny-list (fail-closed) |
| `kiro-secops scan` | project dir | Run scanners; findings block by default |
| `kiro-secops verify` | installed baseline | Self-test guard + integrity check |
| `kiro-secops uninstall` | global or project | Restore previous state from manifest |

## License

MIT-0 (sample code, provided "as is").
