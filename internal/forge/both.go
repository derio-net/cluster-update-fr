package forge

import "context"

// Both pairs the GitHub repository with its Gitea mirror for CI diagnosis.
type Both struct {
	*GitHub
	Mirror *Gitea
}

// GiteaStatuses lists the mirror's statuses for sha.
func (b Both) GiteaStatuses(ctx context.Context, sha string) ([]Status, error) {
	return b.Mirror.Statuses(ctx, sha)
}

// Runs lists the mirror's workflow runs for sha.
func (b Both) Runs(ctx context.Context, sha string) ([]Run, error) { return b.Mirror.Runs(ctx, sha) }

// RerunSupported reports whether the mirror offers a re-run API.
func (b Both) RerunSupported(ctx context.Context) (bool, error) { return b.Mirror.RerunSupported(ctx) }

// Rerun re-runs a mirror workflow run.
func (b Both) Rerun(ctx context.Context, run int64) error { return b.Mirror.Rerun(ctx, run) }
