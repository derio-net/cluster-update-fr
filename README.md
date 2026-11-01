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
| Image | `ghcr.io/derio-net/cluster-update-fr:<semver>` (published on `v*` tags; the release notes carry the pushed `@sha256:` digest — pin by digest) |
| Metrics | `cluster_update_versions_behind{cluster,component}`, `cluster_update_vulns_open{cluster,severity}`, `cluster_update_last_report_timestamp_seconds`, `cluster_update_last_scan_timestamp_seconds`, `cluster_update_updates{state}`, `cluster_update_alarms{state}`, plus `cluster_update_telegram_configured` |
| Session pods | namespace `upgrade-sessions`, labels `fr.run/id=<upgrade-id>`, `cluster-update.fr/type=<chart-major\|stateful\|rollouts\|frank-os\|hop-os>`, ServiceAccount `upgrade-session-<type>` (not for `hop-os`) |
| Session objects | pod `us-<id>-<hash>`, Secrets `…-creds` / `…-brief`, all labelled `app.kubernetes.io/managed-by=cluster-update-fr`; the console writes no RoleBinding — frank pre-binds every role a session needs |
| Session credentials | files under `SESSION_SECRET_DIR`: `github-token` (the **session** App's token, not the console's), `omni-sa-key`, `talosconfig`, `hop-talosconfig`, `hop-kubeconfig` (each type gets only its own) |
| Session PRs | branch `cluster-update/session-<upgrade-id>/<topic>` (`/` cannot occur in an id, so prefixes never collide; the branch names the owning session), author `SESSION_BOT_LOGIN`; merged only by the console on the operator's click |
| Revert PRs | branch `cluster-update/revert-<reverted PR>-<time>`, author `CONSOLE_BOT_LOGIN`; files restored to the merge's parent only if unchanged since the merge (else revert by hand); merged only by the console on the operator's click |
| Required CI | `required_ci_contexts:` in frank's `update-policy.yaml` (exact contexts or `prefix*`; default `gitea-actions/*`), statuses posted by `STATUS_CREATOR_LOGINS` only — never by `CONSOLE_BOT_LOGIN`, even if listed; unset = nothing passes |
| Merge approval | before every console merge (auto-merge, batch, session PR, revert) the console posts commit status `cluster-update/approved` = `success` on the exact verified head SHA — only after every check passed — then merges pinned to that SHA; frank's `main` ruleset requires it from the console App. A PR that failed any check never gets it |
| Briefs | read from frank: `docs/upgrade-briefs/<type>.md`, `docs/upgrade-briefs/AGENTS.md` |
| Hop scan results | VictoriaLogs lines `hop-scan result {"image","namespace","vulnerabilities":[{"id","severity","pkg","installed","fixed","title"}]}` |
| Omni version | JSON file (`OMNI_STATUS_FILE`) `{"version": "..."}` or `omnictl get sysversion -o json` output, written by a Reader-SA sidecar |

### Listeners

| Env | Default | Serves | Who may reach it |
|---|---|---|---|
| `LISTEN` | `:8080` | pages and actions (verified identity required) | Traefik only |
| `OPS_LISTEN` | `:9090` | `/healthz`, `/metrics` — no pages, no actions | kubelet probes, VictoriaMetrics |
| `SESSION_API_LISTEN` | `:8081` | `POST /api/sessions/{id}/step`, `/finish`, `/request-merge` (session step token) | upgrade-session pods |

### Session API

All calls carry `Authorization: Bearer <session-step-token>` (from the
session's own creds Secret). Every field is capped and redacted under a time
bound before it is stored or shown.

| Call | Body | Effect |
|---|---|---|
| `POST …/step` | `{"state":"start\|finish","name":"…"}` (name ≤ 256 B) | pauses / restarts the idle clock; a repeated `start` does not restart the step clock |
| `POST …/request-merge` | `{"pr": N}` | the console verifies PR N against this session's scope and lists it for the operator's **Merge session PR**; `422` names why it was refused |
| `POST …/finish` | `{"outcome":"…","transcript":"…"}` (outcome ≤ 4 KiB, transcript ≤ 1 MiB) | ends the session; the scrubbed transcript goes to History |

### Deployment shape

The console is a **single writer**: `replicas: 1`, Deployment
`strategy: Recreate`, one RWO PVC at `STATE_DIR`. At start it takes an
exclusive `flock` on `STATE_DIR/state.lock` and exits if another process holds
it, so a RollingUpdate overlap or a second replica fails loudly instead of
racing the state file. Session starts write the target lock and the session
record (with its step-token hash) to disk *before* the pod is created, then
record the pod's and Secrets' UIDs. An attach proves the live pod is that
pod (UID, labels, image, ServiceAccount, mounts, no ephemeral containers,
Secret UIDs); anything else is never attached — it is deleted if the console
made it, otherwise refused — and alarmed in `#security`.

## Configuration

Every credential is optional; a missing one disables only what needs it.

| Env | Purpose |
|---|---|
| `GITHUB_TOKEN_FILE` / `GITHUB_TOKEN` | console GitHub App installation token (re-read on use) |
| `GITEA_URL`, `GITEA_REPO`, `GITEA_TOKEN_FILE` | Gitea mirror for CI diagnosis |
| `RENOVATE_BOT_LOGIN`, `CONSOLE_BOT_LOGIN`, `SESSION_BOT_LOGIN`, `TRUSTED_COMMITTERS` (default `web-flow`) | PR trust: only PRs by these bots are acted on (unset = none) |
| `STATUS_CREATOR_LOGINS` | GitHub login(s) of the Gitea→GitHub status bridge; only their statuses count as CI (the console's own never do) — unset = nothing passes |
| `FRANK_REF` (`main`) | the only base branch an update PR may target |
| `AUTHENTIK_JWKS_URL`, `AUTHENTIK_ISSUER`, `AUTHENTIK_AUDIENCE`, `OPERATOR_GROUP` | JWT identity mode (preferred) |
| `PROXY_SECRET_FILE`, `OPERATOR_GROUP` | proxy shared-secret identity mode (fallback) |
| `FRANK_UPDATER_TELEGRAM_BOT_TOKEN`, `_CHAT_ID`, `_SECURITY_THREAD_ID` | the derio.net group's `#security` topic |
| `HOP_KUBECONFIG` | read-only Hop kubeconfig (tailnet). The cluster's `proxy-url` is honoured: `socks5://` / `socks5h://` (e.g. the userspace tailscale sidecar at `socks5://localhost:1055`) dial through a SOCKS5 dialer, `http(s)://` sets the transport proxy; TLS verification against the kubeconfig's CA is unchanged. An invalid or unsupported `proxy-url` refuses the kubeconfig and an unreachable proxy fails the read — never a direct connection. Environment proxy variables are ignored |
| `VICTORIALOGS_URL` | where hop-scan results are read |
| `OMNI_STATUS_FILE` | running Omni version |
| `SESSION_IMAGE`, `SESSION_SECRET_DIR`, `SESSION_API_URL`, `RUNS_FR_URL` | sessions |
| `STATE_DIR` | state file (PVC) |
| `SCAN_INTERVAL` (5m), `CI_TIMEOUT` (30m, from the head's push), `REPORT_HOUR` (8, UTC) | timings |
| `SESSION_IDLE_TIMEOUT` (2h), `SESSION_MAX_LIFETIME` (8h), `SESSION_HARD_CEILING` (2× max lifetime), `SESSION_STEP_CAP` (4h), `SESSION_STEP_TOTAL_CAP` (= max lifetime), `SESSION_MAX_STEP_STARTS` (50) | session lifecycle |
| `SESSION_TRANSCRIPT_MAX` (1 MiB), `SESSION_OUTCOME_MAX` (4 KiB), `SESSION_TRANSCRIPT_SCRUB_TIMEOUT` (10s) | session API caps |

## Security model

- **PR trust** (the frank repo is public): a PR is acted on only if its author
  is the right bot for its branch — Renovate on `renovate/`, the console on
  `cluster-update/batch-` and `cluster-update/revert-<n>-`, the session App on
  `cluster-update/session-<its id>/` — its head is in the repo, its base is
  `main`, every commit is GitHub-signature verified, authored by that bot's
  account and pushed by it, and every changed file lies in the dependency's
  own location. Sensitive paths (`.github/`, `scripts/`, `apps/root/`,
  Hop's `clusters/hop/apps/root/` and updater apps, the policy files) only for
  that dependency on the session path — except an app's own root template,
  which any path may change on its `targetRevision` line alone. On the
  session path an app's own root template stays fully editable — a chart
  major can legitimately need its Helm parameters or value files changed —
  so the **Merge session PR** row lists every changed file, flags sensitive
  paths and calls out `repoURL` / `destination` / sync-policy changes before
  the operator clicks (chosen over narrowing the scope). Every merge
  re-verifies and is pinned to the verified head SHA (batch members are
  merged into the batch branch by SHA too).
- **CI signal**: every declared required context must be `success` (a Gitea
  skipped/warning forwarded as success does not count), posted by the bridge;
  statuses created by the console's own bot never count, so the console
  cannot satisfy its own CI gate (c1d-r12). After the one retry only newer
  results count.
- **Identity**: the UI verifies Authentik's signed JWT (or a proxy shared
  secret), requires the operator group, strips client identity headers, and
  fails closed when neither is configured. Every state change is a
  CSRF-checked POST (attach included); CSP `form-action 'self'`.
- **Cluster writes**: the kube client can only create/delete pods and Secrets
  in the session namespace, named `us-…`, labelled managed-by; a delete reads
  the object first and refuses one the console did not make. No RoleBinding.
- **Sessions**: idle timeout, maximum lifetime, and a hard ceiling plus
  per-step / total-step / step-count caps that end a session even mid-step and
  alarm `#security` (routine lifetime warnings stay in the console). A pod
  that fails verification on any cycle is ended.
- **One session credential** (c1d-r11): every session uses the same session
  GitHub App, so its token can push to any session's branch. Branch ownership
  (`cluster-update/session-<id>/<topic>`) is a **naming rule the console
  checks, not authentication** — a session can write under another session's
  prefix, and GitHub cannot tell the two apart. What bounds the damage: the
  console verifies a session PR against the requesting session's own scope
  (its id, its dependency's files) and merges only the exact head SHA it
  verified, on the operator's click; and frank's branch ruleset keeps `main`
  writable only through the console's approved merges.
- **Credentials**: two redaction layers — exact values of every credential
  the console holds or injects (every file under `SESSION_SECRET_DIR`
  registered at start and each cycle), then patterns — over logs, pages,
  Telegram, PR bodies, session fields and transcripts.
- **Supply chain**: Actions pinned by commit SHA, bases by digest, image with
  provenance + SBOM, least-privilege release jobs.

## Development

```sh
make test   # go test ./... -race
make vet
make build
```
