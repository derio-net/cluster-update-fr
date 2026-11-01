package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/derio-net/cluster-update-fr/internal/scrub"
)

func TestReadTokensAreRegisteredWithTheScrubber(t *testing.T) {
	tok := "inline-" + strings.Repeat("Rt5", 6)
	c, _ := Load(env(map[string]string{"GITEA_TOKEN": tok}))
	_ = c.GiteaToken()
	if strings.Contains(scrub.String("error from gitea with "+tok), tok) {
		t.Fatal("a token the console read must be redacted literally")
	}
}

func env(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func TestLoadDefaultsWithNothingSet(t *testing.T) {
	c, err := Load(env(nil))
	if err != nil {
		t.Fatalf("Load with empty env must not fail: %v", err)
	}
	if c.Listen != ":8080" {
		t.Errorf("Listen = %q, want :8080", c.Listen)
	}
	if c.OpsListen != ":9090" || c.SessionListen != ":8081" {
		t.Errorf("listeners = %q %q", c.OpsListen, c.SessionListen)
	}
	if c.JWKSURL != "" || c.ProxySecretFile != "" || c.OperatorGroup != "" {
		t.Error("identity verification must not be configured by default (the UI fails closed)")
	}
	if c.FrankRepo != "derio-net/frank" {
		t.Errorf("FrankRepo = %q", c.FrankRepo)
	}
	if c.SessionNamespace != "upgrade-sessions" {
		t.Errorf("SessionNamespace = %q", c.SessionNamespace)
	}
	if c.GitHubToken() != "" || c.GiteaToken() != "" {
		t.Error("tokens must be empty when unset")
	}
	if c.Telegram.Configured() {
		t.Error("telegram must be unconfigured when unset")
	}
	if c.IdleTimeout != 2*time.Hour || c.MaxLifetime != 8*time.Hour {
		t.Errorf("session timeouts = %v / %v", c.IdleTimeout, c.MaxLifetime)
	}
	if c.ScanInterval != 5*time.Minute {
		t.Errorf("ScanInterval = %v", c.ScanInterval)
	}
	if c.ReportHour != 8 {
		t.Errorf("ReportHour = %d", c.ReportHour)
	}
}

func TestTokensFromFilesAreReadLiveAndTrimmed(t *testing.T) {
	dir := t.TempDir()
	gh := filepath.Join(dir, "gh")
	if err := os.WriteFile(gh, []byte("first\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := Load(env(map[string]string{"GITHUB_TOKEN_FILE": gh, "GITEA_TOKEN": "inline"}))
	if err != nil {
		t.Fatal(err)
	}
	if c.GitHubToken() != "first" {
		t.Errorf("GitHubToken = %q", c.GitHubToken())
	}
	// GitHub App installation tokens rotate (~1h); the file is re-read.
	if err := os.WriteFile(gh, []byte("second"), 0o600); err != nil {
		t.Fatal(err)
	}
	if c.GitHubToken() != "second" {
		t.Errorf("rotated GitHubToken = %q", c.GitHubToken())
	}
	if c.GiteaToken() != "inline" {
		t.Errorf("GiteaToken = %q", c.GiteaToken())
	}
}

func TestMissingTokenFileDegradesToEmpty(t *testing.T) {
	c, err := Load(env(map[string]string{"GITHUB_TOKEN_FILE": "/nonexistent/x"}))
	if err != nil {
		t.Fatalf("a missing optional secret must not fail Load: %v", err)
	}
	if c.GitHubToken() != "" {
		t.Error("missing file must read as empty")
	}
}

func TestTelegramConfigured(t *testing.T) {
	c, _ := Load(env(map[string]string{
		"FRANK_UPDATER_TELEGRAM_BOT_TOKEN":          "x",
		"FRANK_UPDATER_TELEGRAM_CHAT_ID":            "-1001",
		"FRANK_UPDATER_TELEGRAM_SECURITY_THREAD_ID": "7",
	}))
	if !c.Telegram.Configured() {
		t.Fatal("telegram should be configured")
	}
	if c.Telegram.ChatID != "-1001" || c.Telegram.ThreadID != "7" {
		t.Errorf("telegram = %+v", c.Telegram)
	}
	c2, _ := Load(env(map[string]string{"FRANK_UPDATER_TELEGRAM_BOT_TOKEN": "x", "FRANK_UPDATER_TELEGRAM_CHAT_ID": "-1"}))
	if c2.Telegram.Configured() {
		t.Error("without a thread id the bot must not post (it would land outside #security)")
	}
}

func TestSessionHardCeilingAndStepCap(t *testing.T) {
	c, err := Load(env(map[string]string{}))
	if err != nil {
		t.Fatal(err)
	}
	if c.HardCeiling != 16*time.Hour || c.StepCap != 4*time.Hour {
		t.Errorf("defaults: ceiling %v, step cap %v", c.HardCeiling, c.StepCap)
	}
	c, _ = Load(env(map[string]string{"SESSION_MAX_LIFETIME": "3h"}))
	if c.HardCeiling != 6*time.Hour {
		t.Errorf("ceiling must default to 2x max lifetime: %v", c.HardCeiling)
	}
	c, _ = Load(env(map[string]string{"SESSION_HARD_CEILING": "10h", "SESSION_STEP_CAP": "90m"}))
	if c.HardCeiling != 10*time.Hour || c.StepCap != 90*time.Minute {
		t.Errorf("explicit: %v / %v", c.HardCeiling, c.StepCap)
	}
	if _, err := Load(env(map[string]string{"SESSION_HARD_CEILING": "1h"})); err == nil {
		t.Error("a ceiling below the max lifetime must be refused")
	}
}

func TestBadDurationIsAnError(t *testing.T) {
	if _, err := Load(env(map[string]string{"SCAN_INTERVAL": "soon"})); err == nil {
		t.Fatal("want error for malformed duration")
	}
}
