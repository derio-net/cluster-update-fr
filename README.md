# cluster-update-fr

The update console for the derio-net homelab clusters (Frank and Hop): one web
page that lists every dependency of both clusters with its declared, running
and latest version and its known vulnerabilities, alarms on security findings
in a dedicated Telegram topic, merges approved updates through the forges (it
is the only merger — Renovate never auto-merges), proves every update with
ArgoCD's applied revision plus a smoke test, and launches disposable, scoped
upgrade-session pods for the updates that need a human-guided agent. It never
writes to a cluster except to create and delete those session pods. Design:
[Update & Security Lifecycle](https://github.com/derio-net/frank/blob/main/docs/superpowers/specs/2026-10-31--life--update-security-lifecycle-design.md)
in derio-net/frank.
