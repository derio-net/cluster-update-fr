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

## Execution

Phases 1–5 are implemented inline by one agent (no subagent dispatch was
available to the cross-repo agent). Phase 6 is the operator's.
