# Cluster update console — cluster-update-fr plan

**Spec:** `derio-net/frank:docs/superpowers/specs/2026-10-31--life--update-security-lifecycle-design.md`
**Status:** In Progress
**Layer:** `life` (22, defined in derio-net/frank)

## What this plan builds

The console app of the Update & Security Lifecycle (spec Part 2 and the
launcher half of Part 3): inventory, Needs action / Inventory / History pages,
the merge engine (the console is the ONLY merger), CI diagnosis and one-retry
recovery, the update state machine with verification, alarm state + Telegram +
daily report, exported metrics, and the disposable upgrade-session launcher.

Frank (sibling plan `2026-10-31--life--update-security-lifecycle`) owns the
deployment: namespace `upgrade-sessions`, per-type ServiceAccounts, the
RoleBinding template, network policies, briefs, smoke declarations, versions
files, Renovate. This repo only reads those and creates/deletes session pods,
their Secrets and the per-upgrade RoleBinding.

## Interface contract (frank depends on these names)

- Image `ghcr.io/derio-net/cluster-update-fr:<semver>` (release workflow on `v*` tags).
- Metrics: `cluster_update_versions_behind{cluster,component}`,
  `cluster_update_vulns_open{cluster,severity}`,
  `cluster_update_last_report_timestamp_seconds`,
  `cluster_update_last_scan_timestamp_seconds`, `cluster_update_updates{state}`,
  `cluster_update_alarms{state}`.
- Session pods: namespace `upgrade-sessions`, labels `fr.run/id=<upgrade-id>`,
  `cluster-update.fr/type=<chart-major|stateful|rollouts|frank-os|hop-os>`.
- Env: `FRANK_UPDATER_TELEGRAM_BOT_TOKEN`, `_CHAT_ID`, `_SECURITY_THREAD_ID`,
  GitHub App token and Gitea token from files or env — all optional; the app
  degrades, never crashes.
- Trusted auth header `X-authentik-username`.

## Decisions taken while planning

- Go, standard library only plus `gopkg.in/yaml.v3`: a minimal Kubernetes REST
  client instead of client-go, so the write surface is visible in one file and
  restricted by construction (R14).
- State in one JSON file on the PVC (atomic temp+rename). One replica.
- Gitea 1.25.4 (measured 2026-10-31 at `/api/v1/version`) exposes NO job
  re-run endpoint in `/swagger.v1.json`; the console probes the swagger at
  start and falls back to Renovate's rebase checkbox, never an empty commit.

## Phase splits and tiers

The spec lives in derio-net/frank, so this repo has no same-repo spec journal
to hold `phase-split-*` / `tier-*` decisions (`fr journal add --scope spec`
refuses an orphaned slug). The decisions are recorded here instead:

- **p1 (skeleton):** R1 inventory + R25 scrubbing — the foundation every later
  phase reads; carries the CI smoke.
- **p2 — ask:** the forge engine (R6, R7, R9, R14, R19, R28): countdown, batch,
  security-first merging and CI diagnosis are one reviewable ask.
- **p3 — ask:** state machine, verification, history, alarms, report, metrics
  (R10, R11, R12, R15, R16, R26) — "done means verified" and the quiet alarm.
- **p4 — ask + tier hard:** disposable sessions (R20–R23, R29). It is the
  console's only cluster-write path and holds the per-target lock every Start
  relies on; the paused-idle-clock rule is a judgement the spec leaves open.
- **p5 — ask:** the pages and the main loop (R13, R18/R19 display), built last
  on the engine, store and session APIs.

## Execution

Phases 1–5 are implemented inline by one agent (no subagent dispatch was
available to the cross-repo agent). Phase 6 is the operator's.
