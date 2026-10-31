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
	Listen     string
	AuthHeader string // trusted header set (and overwritten) by Authentik forward-auth
	ConsoleURL string // public URL used in Telegram links

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
	RunsFrURL        string // attach UI base URL

	ScanInterval time.Duration
	CITimeout    time.Duration
	IdleTimeout  time.Duration
	MaxLifetime  time.Duration
	ReportHour   int // UTC hour of the daily report

	Telegram Telegram

	githubToken     string
	githubTokenFile string
	giteaToken      string
	giteaTokenFile  string
}

// GitHubToken returns the current GitHub App installation token, or "".
func (c *Config) GitHubToken() string { return secret(c.githubToken, c.githubTokenFile) }

// GiteaToken returns the Gitea Actions token, or "".
func (c *Config) GiteaToken() string { return secret(c.giteaToken, c.giteaTokenFile) }

func secret(inline, file string) string {
	if file != "" {
		b, err := os.ReadFile(file)
		if err != nil {
			return ""
		}
		return strings.TrimSpace(string(b))
	}
	return strings.TrimSpace(inline)
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
		Listen:           get("LISTEN", ":8080"),
		AuthHeader:       get("AUTH_HEADER", "X-authentik-username"),
		ConsoleURL:       get("CONSOLE_URL", "https://updates.cluster.derio.net"),
		FrankRepo:        get("FRANK_REPO", "derio-net/frank"),
		FrankRef:         get("FRANK_REF", "main"),
		GitHubAPI:        strings.TrimRight(get("GITHUB_API", "https://api.github.com"), "/"),
		GiteaURL:         strings.TrimRight(get("GITEA_URL", ""), "/"),
		StateDir:         get("STATE_DIR", "/var/lib/cluster-update-fr"),
		HopKubeconfig:    get("HOP_KUBECONFIG", ""),
		OmniStatusFile:   get("OMNI_STATUS_FILE", ""),
		SessionNamespace: get("SESSION_NAMESPACE", "upgrade-sessions"),
		SessionImage:     get("SESSION_IMAGE", ""),
		SessionSecretDir: get("SESSION_SECRET_DIR", ""),
		RunsFrURL:        strings.TrimRight(get("RUNS_FR_URL", "https://sessions.cluster.derio.net"), "/"),
		Telegram: Telegram{
			BotToken: secret(getenv("FRANK_UPDATER_TELEGRAM_BOT_TOKEN"), getenv("FRANK_UPDATER_TELEGRAM_BOT_TOKEN_FILE")),
			ChatID:   strings.TrimSpace(getenv("FRANK_UPDATER_TELEGRAM_CHAT_ID")),
			ThreadID: strings.TrimSpace(getenv("FRANK_UPDATER_TELEGRAM_SECURITY_THREAD_ID")),
		},
		githubToken:     getenv("GITHUB_TOKEN"),
		githubTokenFile: getenv("GITHUB_TOKEN_FILE"),
		giteaToken:      getenv("GITEA_TOKEN"),
		giteaTokenFile:  getenv("GITEA_TOKEN_FILE"),
	}
	c.GiteaRepo = get("GITEA_REPO", c.FrankRepo)

	durations := []struct {
		key string
		def time.Duration
		dst *time.Duration
	}{
		{"SCAN_INTERVAL", 5 * time.Minute, &c.ScanInterval},
		{"CI_TIMEOUT", 30 * time.Minute, &c.CITimeout},
		{"SESSION_IDLE_TIMEOUT", 2 * time.Hour, &c.IdleTimeout},
		{"SESSION_MAX_LIFETIME", 8 * time.Hour, &c.MaxLifetime},
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
