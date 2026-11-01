// Package config loads the console's configuration from the environment.
//
// Every credential is optional: a missing token, file or chat id disables the
// feature that needs it (the UI shows the action as unavailable) and never
// stops the process. Secrets given as *_FILE are re-read on every use, because
// GitHub App installation tokens are rotated by ESO roughly hourly.
package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/derio-net/cluster-update-fr/internal/scrub"
)

// Telegram is the dedicated update chat: the derio.net group's #security topic.
type Telegram struct {
	BotToken string
	ChatID   string // kept as a string: supergroup ids are negative (-100…)
	ThreadID string // message_thread_id of the #security topic
}

// Configured reports whether the bot may post. Without a thread id a message
// would land in the group's General topic, outside the bot's own topic, so
// the bot stays silent instead.
func (t Telegram) Configured() bool {
	return t.BotToken != "" && t.ChatID != "" && t.ThreadID != ""
}

// Config is the full runtime configuration.
type Config struct {
	Listen        string // UI (pages + actions; only Traefik may reach it)
	OpsListen     string // /healthz + /metrics
	SessionListen string // session step/finish API (session pods only)
	SessionAPIURL string // how a session pod reaches SessionListen
	ConsoleURL    string // public URL used in Telegram links

	// Identity (see internal/identity): JWT mode when the JWKS URL, issuer
	// and audience are set; else proxy-secret mode when the secret file is
	// set; else every UI request is refused.
	JWKSURL         string
	JWTIssuer       string
	JWTAudience     string
	ProxySecretFile string
	OperatorGroup   string

	VictoriaLogsURL string // where Frank's hop-scan job's results land

	FrankRepo string // owner/name of the declarations repo on GitHub
	FrankRef  string
	GitHubAPI string
	GiteaURL  string // Gitea base URL (API under /api/v1)
	GiteaRepo string // owner/name of the Gitea mirror of FrankRepo

	StateDir string

	HopKubeconfig  string // read-only Hop kubeconfig (over the tailnet)
	OmniStatusFile string // JSON written by the Reader-SA omnictl sidecar

	SessionNamespace string
	SessionImage     string
	SessionSecretDir string // directory of per-type credential files (mounted by frank)
	// SessionTailscaleImage is the userspace tailscale sidecar of hop-os
	// sessions, pinned by digest (…@sha256:<64 hex>); unset or unpinned =
	// hop-os sessions cannot start.
	SessionTailscaleImage       string
	SessionTailscaleLoginServer string // Headscale URL (default https://headscale.hop.derio.net)
	SessionTailscaleTag         string // tag hop-os sessions join as (default tag:frank-session; never tag:frank-updater)
	RunsFrURL                   string // attach UI base URL

	// PR trust (the frank repo is public): only PRs by these bots are acted on.
	RenovateBot       string   // login of the Renovate GitHub App bot, e.g. "renovate-frank[bot]"
	ConsoleBot        string   // login of the console's GitHub App bot (batch PRs)
	SessionBot        string   // login of the upgrade sessions' GitHub App bot (session PRs)
	TrustedCommitters []string // extra committer logins (GitHub's web-flow for API commits)
	// StatusCreators are the GitHub logins whose commit statuses count as
	// CI (the Gitea→GitHub status bridge); the console bot is added too.
	StatusCreators []string

	ScanInterval time.Duration
	CITimeout    time.Duration
	IdleTimeout  time.Duration
	MaxLifetime  time.Duration
	// HardCeiling ends a session unconditionally, even mid-step, and alarms
	// (default 2× MaxLifetime); StepCap ends a session whose single step
	// runs longer (default 4h). A steered agent cannot hold credentials by
	// reporting a step as running forever (c1s-r1).
	HardCeiling time.Duration
	StepCap     time.Duration
	// StepTotalCap bounds a session's summed step-running time (default =
	// MaxLifetime) and MaxStepStarts its number of step starts (default 50).
	StepTotalCap  time.Duration
	MaxStepStarts int
	// TranscriptMax caps a session transcript (bytes, default 1 MiB);
	// TranscriptScrubTimeout bounds its redaction (default 10s).
	TranscriptMax          int
	OutcomeMax             int // a session's finish outcome (bytes, default 4 KiB)
	TranscriptScrubTimeout time.Duration
	ReportHour             int // UTC hour of the daily report

	Telegram Telegram

	githubToken     string
	githubTokenFile string
	giteaToken      string
	giteaTokenFile  string
}

// GitHubToken returns the current GitHub App installation token, or "".
func (c *Config) GitHubToken() string {
	return secret("github-token", c.githubToken, c.githubTokenFile)
}

// GiteaToken returns the Gitea Actions token, or "".
func (c *Config) GiteaToken() string { return secret("gitea-token", c.giteaToken, c.giteaTokenFile) }

// secret reads a credential and registers it with the scrubber, so its
// literal value is redacted everywhere before any pattern runs (R25).
func secret(kind, inline, file string) string {
	v := strings.TrimSpace(inline)
	if file != "" {
		b, err := os.ReadFile(file)
		if err != nil {
			return ""
		}
		v = strings.TrimSpace(string(b))
	}
	scrub.Register(kind, v)
	return v
}

// Load reads the configuration through getenv (os.Getenv in production).
func Load(getenv func(string) string) (*Config, error) {
	get := func(k, def string) string {
		if v := strings.TrimSpace(getenv(k)); v != "" {
			return v
		}
		return def
	}
	c := &Config{
		Listen:                      get("LISTEN", ":8080"),
		OpsListen:                   get("OPS_LISTEN", ":9090"),
		SessionListen:               get("SESSION_API_LISTEN", ":8081"),
		SessionAPIURL:               strings.TrimRight(get("SESSION_API_URL", ""), "/"),
		ConsoleURL:                  get("CONSOLE_URL", "https://updates.cluster.derio.net"),
		JWKSURL:                     get("AUTHENTIK_JWKS_URL", ""),
		JWTIssuer:                   get("AUTHENTIK_ISSUER", ""),
		JWTAudience:                 get("AUTHENTIK_AUDIENCE", ""),
		ProxySecretFile:             get("PROXY_SECRET_FILE", ""),
		OperatorGroup:               get("OPERATOR_GROUP", ""),
		VictoriaLogsURL:             strings.TrimRight(get("VICTORIALOGS_URL", ""), "/"),
		FrankRepo:                   get("FRANK_REPO", "derio-net/frank"),
		FrankRef:                    get("FRANK_REF", "main"),
		GitHubAPI:                   strings.TrimRight(get("GITHUB_API", "https://api.github.com"), "/"),
		GiteaURL:                    strings.TrimRight(get("GITEA_URL", ""), "/"),
		StateDir:                    get("STATE_DIR", "/var/lib/cluster-update-fr"),
		HopKubeconfig:               get("HOP_KUBECONFIG", ""),
		OmniStatusFile:              get("OMNI_STATUS_FILE", ""),
		SessionNamespace:            get("SESSION_NAMESPACE", "upgrade-sessions"),
		SessionImage:                get("SESSION_IMAGE", ""),
		SessionSecretDir:            get("SESSION_SECRET_DIR", ""),
		SessionTailscaleImage:       get("SESSION_TAILSCALE_IMAGE", ""),
		SessionTailscaleLoginServer: get("SESSION_TAILSCALE_LOGIN_SERVER", "https://headscale.hop.derio.net"),
		SessionTailscaleTag:         get("SESSION_TAILSCALE_TAG", "tag:frank-session"),
		RunsFrURL:                   strings.TrimRight(get("RUNS_FR_URL", "https://sessions.cluster.derio.net"), "/"),
		Telegram: Telegram{
			BotToken: secret("telegram-bot-token", getenv("FRANK_UPDATER_TELEGRAM_BOT_TOKEN"), getenv("FRANK_UPDATER_TELEGRAM_BOT_TOKEN_FILE")),
			ChatID:   strings.TrimSpace(getenv("FRANK_UPDATER_TELEGRAM_CHAT_ID")),
			ThreadID: strings.TrimSpace(getenv("FRANK_UPDATER_TELEGRAM_SECURITY_THREAD_ID")),
		},
		githubToken:     getenv("GITHUB_TOKEN"),
		githubTokenFile: getenv("GITHUB_TOKEN_FILE"),
		giteaToken:      getenv("GITEA_TOKEN"),
		giteaTokenFile:  getenv("GITEA_TOKEN_FILE"),
	}
	c.GiteaRepo = get("GITEA_REPO", c.FrankRepo)
	c.RenovateBot = get("RENOVATE_BOT_LOGIN", "")
	c.ConsoleBot = get("CONSOLE_BOT_LOGIN", "")
	c.SessionBot = get("SESSION_BOT_LOGIN", "")
	c.StatusCreators = strings.Fields(strings.ReplaceAll(get("STATUS_CREATOR_LOGINS", ""), ",", " "))
	c.TrustedCommitters = strings.Fields(strings.ReplaceAll(get("TRUSTED_COMMITTERS", "web-flow"), ",", " "))

	durations := []struct {
		key string
		def time.Duration
		dst *time.Duration
	}{
		{"SCAN_INTERVAL", 5 * time.Minute, &c.ScanInterval},
		{"CI_TIMEOUT", 30 * time.Minute, &c.CITimeout},
		{"SESSION_IDLE_TIMEOUT", 2 * time.Hour, &c.IdleTimeout},
		{"SESSION_MAX_LIFETIME", 8 * time.Hour, &c.MaxLifetime},
		{"SESSION_HARD_CEILING", 0, &c.HardCeiling}, // 0 here = derive below
		{"SESSION_STEP_CAP", 4 * time.Hour, &c.StepCap},
		{"SESSION_STEP_TOTAL_CAP", 0, &c.StepTotalCap}, // 0 here = MaxLifetime
		{"SESSION_TRANSCRIPT_SCRUB_TIMEOUT", 10 * time.Second, &c.TranscriptScrubTimeout},
	}
	for _, d := range durations {
		*d.dst = d.def
		if v := strings.TrimSpace(getenv(d.key)); v != "" {
			parsed, err := time.ParseDuration(v)
			if err != nil || parsed <= 0 {
				return nil, fmt.Errorf("config: %s=%q is not a positive duration", d.key, v)
			}
			*d.dst = parsed
		}
	}
	if c.StepTotalCap == 0 {
		c.StepTotalCap = c.MaxLifetime
	}
	c.TranscriptMax = 1 << 20
	if v := strings.TrimSpace(getenv("SESSION_TRANSCRIPT_MAX")); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1024 || n > 64<<20 {
			return nil, fmt.Errorf("config: SESSION_TRANSCRIPT_MAX=%q must be bytes between 1024 and 67108864", v)
		}
		c.TranscriptMax = n
	}
	c.OutcomeMax = 4096
	if v := strings.TrimSpace(getenv("SESSION_OUTCOME_MAX")); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 64 || n > 64<<10 {
			return nil, fmt.Errorf("config: SESSION_OUTCOME_MAX=%q must be bytes between 64 and 65536", v)
		}
		c.OutcomeMax = n
	}
	c.MaxStepStarts = 50
	if v := strings.TrimSpace(getenv("SESSION_MAX_STEP_STARTS")); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 {
			return nil, fmt.Errorf("config: SESSION_MAX_STEP_STARTS=%q must be a positive integer", v)
		}
		c.MaxStepStarts = n
	}
	if c.HardCeiling == 0 {
		c.HardCeiling = 2 * c.MaxLifetime
	}
	if c.HardCeiling < c.MaxLifetime {
		return nil, fmt.Errorf("config: SESSION_HARD_CEILING=%s must be at least SESSION_MAX_LIFETIME=%s", c.HardCeiling, c.MaxLifetime)
	}
	c.ReportHour = 8
	if v := strings.TrimSpace(getenv("REPORT_HOUR")); v != "" {
		h, err := strconv.Atoi(v)
		if err != nil || h < 0 || h > 23 {
			return nil, fmt.Errorf("config: REPORT_HOUR=%q must be 0-23", v)
		}
		c.ReportHour = h
	}
	return c, nil
}
