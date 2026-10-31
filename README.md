# cluster-update-fr

The update console for the derio-net homelab clusters (Frank and Hop): one web
page that lists every dependency of both clusters with its declared, running
and latest version and its known vulnerabilities, alarms on security findings
in a dedicated Telegram topic, merges approved updates through the forges (it
is the only merger — Renovate never auto-merges), proves every update with
ArgoCD's applied revision plus a smoke test, and launches disposable, scoped
upgrade-session pods for the updates that need a human-guided agent. It never
writes to a cluster except to create and delete those session pods and their
Secrets. Design:
[Update & Security Lifecycle](https://github.com/derio-net/frank/blob/main/docs/superpowers/specs/2026-10-31--life--update-security-lifecycle-design.md)
in derio-net/frank; deployment lives in frank (`apps/cluster-update-fr/`).

## Pages

- **Needs action** — Security (first; *Approve now* or *Start session*),
  Suggested batch (editable, *Approve batch* → one PR), Auto-merge countdowns
  (*Hold* / *Merge now*), Guided upgrades (OS tracks step by step, Omni with a
  runbook link), Rollouts waiting for a decision, Held — CI (diagnosis +
  *Retry CI*), and untrusted PRs (read-only). Every item shows its rollback
  path before its approve button.
- **Inventory** — cluster → service → dependency: declared / running / latest
  / gap, vulnerabilities, update path.
- **History** — every update with approver, PR, rollout, verification,
  scrubbed session transcript and a *Revert* button.

## Interface contract (derio-net/frank depends on these)

| What | Value |
|---|---|
| Image | `ghcr.io/derio-net/cluster-update-fr:<semver>` (published on `v*` tags) |
| Metrics | `cluster_update_versions_behind{cluster,component}`, `cluster_update_vulns_open{cluster,severity}`, `cluster_update_last_report_timestamp_seconds`, `cluster_update_last_scan_timestamp_seconds`, `cluster_update_updates{state}`, `cluster_update_alarms{state}`, plus `cluster_update_telegram_configured` |
| Session pods | namespace `upgrade-sessions`, labels `fr.run/id=<upgrade-id>`, `cluster-update.fr/type=<chart-major\|stateful\|rollouts\|frank-os\|hop-os>`, ServiceAccount `upgrade-session-<type>` (not for `hop-os`) |
| Session credentials | files under `SESSION_SECRET_DIR`: `github-token`, `omni-sa-key`, `talosconfig`, `hop-talosconfig`, `hop-kubeconfig` (each type gets only its own) |
| Briefs | read from frank: `docs/upgrade-briefs/<type>.md`, `docs/upgrade-briefs/AGENTS.md` |
| Hop scan results | VictoriaLogs lines `hop-scan result {"image","namespace","vulnerabilities":[{"id","severity","pkg","installed","fixed","title"}]}` |
| Omni version | JSON file (`OMNI_STATUS_FILE`) `{"version": "..."}` or `omnictl get sysversion -o json` output, written by a Reader-SA sidecar |

### Listeners

| Env | Default | Serves | Who may reach it |
|---|---|---|---|
| `LISTEN` | `:8080` | pages and actions (verified identity required) | Traefik only |
| `OPS_LISTEN` | `:9090` | `/healthz`, `/metrics` — no pages, no actions | kubelet probes, VictoriaMetrics |
| `SESSION_API_LISTEN` | `:8081` | `POST /api/sessions/{id}/step`, `/finish` (session step token) | upgrade-session pods |

## Configuration

Every credential is optional; a missing one disables only what needs it.

| Env | Purpose |
|---|---|
| `GITHUB_TOKEN_FILE` / `GITHUB_TOKEN` | console GitHub App installation token (re-read on use) |
| `GITEA_URL`, `GITEA_REPO`, `GITEA_TOKEN_FILE` | Gitea mirror for CI diagnosis |
| `RENOVATE_BOT_LOGIN`, `CONSOLE_BOT_LOGIN`, `TRUSTED_COMMITTERS` (default `web-flow`) | PR trust: only PRs by these bots are acted on (unset = none) |
| `AUTHENTIK_JWKS_URL`, `AUTHENTIK_ISSUER`, `AUTHENTIK_AUDIENCE`, `OPERATOR_GROUP` | JWT identity mode (preferred) |
| `PROXY_SECRET_FILE`, `OPERATOR_GROUP` | proxy shared-secret identity mode (fallback) |
| `FRANK_UPDATER_TELEGRAM_BOT_TOKEN`, `_CHAT_ID`, `_SECURITY_THREAD_ID` | the derio.net group's `#security` topic |
| `HOP_KUBECONFIG` | read-only Hop kubeconfig (tailnet) |
| `VICTORIALOGS_URL` | where hop-scan results are read |
| `OMNI_STATUS_FILE` | running Omni version |
| `SESSION_IMAGE`, `SESSION_SECRET_DIR`, `SESSION_API_URL`, `RUNS_FR_URL` | sessions |
| `STATE_DIR` | state file (PVC) |
| `SCAN_INTERVAL` (5m), `CI_TIMEOUT` (30m), `SESSION_IDLE_TIMEOUT` (2h), `SESSION_MAX_LIFETIME` (8h), `REPORT_HOUR` (8, UTC) | timings |

## Security model

- **PR trust** (the frank repo is public): a PR is acted on only if its author
  is the Renovate bot (batch PRs: the console's bot), its head is in the repo
  on `renovate/` or `cluster-update/batch-`, every commit is GitHub-signature
  verified and authored by the bot's account, and every changed file lies in
  the dependency's own location (sensitive paths only for that dependency on
  the session path). Merges re-verify and pin the head SHA.
- **Identity**: the UI verifies Authentik's signed JWT (or a proxy shared
  secret), requires the operator group, strips client identity headers, and
  fails closed when neither is configured.
- **Cluster writes**: the kube client can only create/delete pods, Secrets
  and RoleBindings in the session namespace; everything else is refused
  before a request is built.
- **Credentials**: two redaction layers — exact values of every credential
  the console holds or injects (with encoded forms), then patterns — over
  logs, pages, Telegram, PR bodies and transcripts.

## Development

```sh
make test   # go test ./... -race
make vet
make build
```
