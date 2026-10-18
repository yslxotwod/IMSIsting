# AGENTS.md

Guidance for AI coding agents working in this repository.

## Agent skills

### Issue tracker

GitHub Issues on `yslxotwod/IMSIsting`, driven by the `gh` CLI. See `docs/agents/issue-tracker.md`.

### Triage labels

Five canonical triage roles, all with their default names: `needs-triage`, `needs-info`, `ready-for-agent`, `ready-for-human`, `wontfix`. See `docs/agents/triage-labels.md`.

### Wayfinder labels

Owner-qualified `wayfinder:` labels only — `wayfinder:map`, `wayfinder:research`, `wayfinder:prototype`, `wayfinder:grilling`, `wayfinder:task`. See `docs/agents/wayfinder-labels.md`.

### Domain docs

Domain docs are single-context: one `GLOSSARY.md` at the repo root, architecture decisions in `docs/adr/`. See `docs/agents/domain.md`.

## Working rules

### Commit and push at the end of every finished phase

When a roadmap phase in `docs/OFFENSIVE_ROADMAP.md` is finished — gates green,
suite green, docs updated — commit the work and push it. Do not leave a finished
phase sitting in the working tree: the phase is not done until it is on the
remote. The message names the phase and what it changed, not just "update".

Sub-work inside a phase does not need its own commit; the phase boundary is the
commit boundary. If a phase is half-finished, it is not committed as if it were
done — say so in the response instead.
