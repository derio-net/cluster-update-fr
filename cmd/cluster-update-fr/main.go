// Command cluster-update-fr serves the update console.
//
// Listeners (frank's NetworkPolicy matches them):
//
//	LISTEN             :8080  UI — pages and actions; reachable from Traefik only
//	OPS_LISTEN         :9090  /healthz and /metrics — probes and VictoriaMetrics
//	SESSION_API_LISTEN :8081  session step/finish API — upgrade-session pods only
package main

import (
	"context"
	"crypto/rand"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/derio-net/cluster-update-fr/internal/app"
	"github.com/derio-net/cluster-update-fr/internal/config"
	"github.com/derio-net/cluster-update-fr/internal/forge"
	"github.com/derio-net/cluster-update-fr/internal/frankrepo"
	"github.com/derio-net/cluster-update-fr/internal/identity"
	"github.com/derio-net/cluster-update-fr/internal/kube"
	"github.com/derio-net/cluster-update-fr/internal/live"
	"github.com/derio-net/cluster-update-fr/internal/scrub"
	"github.com/derio-net/cluster-update-fr/internal/session"
	"github.com/derio-net/cluster-update-fr/internal/store"
	"github.com/derio-net/cluster-update-fr/internal/telegram"
	"github.com/derio-net/cluster-update-fr/internal/verify"
	"github.com/derio-net/cluster-update-fr/internal/web"
)

func main() {
	logger := log.New(scrub.Writer(os.Stderr), "", log.LstdFlags|log.LUTC)
	log.SetOutput(scrub.Writer(os.Stderr))
	cfg, err := config.Load(os.Getenv)
	if err != nil {
		logger.Fatal(err)
	}
	st, err := store.Open(cfg.StateDir, nil)
	if err != nil {
		logger.Fatal(err)
	}
	if st.Warning != "" {
		logger.Print(st.Warning)
	}
	httpc := &http.Client{Timeout: 30 * time.Second}

	gh := &forge.GitHub{API: cfg.GitHubAPI, Repo: cfg.FrankRepo, Token: cfg.GitHubToken, HTTP: httpc}
	a := &app.App{Cfg: cfg, Store: st, GitHub: gh, Ancestry: gh, Log: logger,
		Repo:  frankrepo.GitHubSource{API: cfg.GitHubAPI, Repo: cfg.FrankRepo, Ref: cfg.FrankRef, Token: cfg.GitHubToken, HTTP: httpc},
		Smoke: verify.Runner{HTTP: &http.Client{Timeout: 15 * time.Second}}.Run}
	if cfg.GiteaURL != "" {
		a.Diag = forge.Both{GitHub: gh, Mirror: &forge.Gitea{URL: cfg.GiteaURL, Repo: cfg.GiteaRepo, Token: cfg.GiteaToken, HTTP: httpc}}
	}
	if cfg.Telegram.Configured() {
		a.Telegram = &telegram.Client{Cfg: cfg.Telegram, HTTP: httpc}
	} else {
		logger.Print("telegram: not configured; alarms and reports are kept but not sent")
	}
	if frank, err := kube.InCluster(); err != nil {
		logger.Printf("frank: no in-cluster credentials (%v); live reads and sessions disabled", err)
	} else {
		frank.Writes = &kube.WritePolicy{SessionNamespace: cfg.SessionNamespace}
		a.Frank = frank
		a.Launcher = &session.Launcher{Kube: frank, Store: st, Namespace: cfg.SessionNamespace, Image: cfg.SessionImage,
			CredDir: cfg.SessionSecretDir, ConsoleURL: cfg.SessionAPIURL, IdleTimeout: cfg.IdleTimeout, MaxLifetime: cfg.MaxLifetime,
			HardCeiling: cfg.HardCeiling, StepCap: cfg.StepCap, StepTotalCap: cfg.StepTotalCap, MaxStepStarts: cfg.MaxStepStarts,
			TranscriptMax: cfg.TranscriptMax, OutcomeMax: cfg.OutcomeMax, ScrubTimeout: cfg.TranscriptScrubTimeout,
			TailscaleImage: cfg.SessionTailscaleImage, TailscaleLoginServer: cfg.SessionTailscaleLoginServer, TailscaleTag: cfg.SessionTailscaleTag}
		a.Launcher.RegisterCredentials() // before any listener serves a byte (c1s-r5)
	}
	if cfg.HopKubeconfig != "" {
		if hop, err := kube.FromKubeconfig(cfg.HopKubeconfig); err != nil {
			logger.Printf("hop: %v; Hop shows as unknown", err)
		} else {
			a.Hop = hop
		}
	}
	if cfg.VictoriaLogsURL != "" {
		a.HopScan = func(ctx context.Context) ([]live.Report, error) { return live.HopScan(ctx, httpc, cfg.VictoriaLogsURL) }
	}

	var auth identity.Authenticator = identity.Refuse{}
	switch {
	case cfg.JWKSURL != "" && cfg.JWTIssuer != "" && cfg.JWTAudience != "" && cfg.OperatorGroup != "":
		auth = &identity.JWT{JWKSURL: cfg.JWKSURL, Issuer: cfg.JWTIssuer, Audience: cfg.JWTAudience, Group: cfg.OperatorGroup, HTTP: httpc}
		logger.Print("identity: verifying Authentik JWTs")
	case cfg.ProxySecretFile != "" && cfg.OperatorGroup != "":
		auth = identity.ProxySecret{SecretFile: cfg.ProxySecretFile, Group: cfg.OperatorGroup}
		logger.Print("identity: proxy shared-secret mode")
	default:
		logger.Print("identity: NOT configured — the UI refuses every request")
	}
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		logger.Fatal(err)
	}
	h := web.New(a, web.Options{Auth: auth, Secret: secret, TranscriptMax: cfg.TranscriptMax})

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, os.Interrupt)
	defer stop()
	servers := []*http.Server{
		{Addr: cfg.Listen, Handler: h.UI},
		{Addr: cfg.OpsListen, Handler: h.Ops},
		{Addr: cfg.SessionListen, Handler: h.Session},
	}
	for _, s := range servers {
		s.ReadHeaderTimeout, s.ReadTimeout, s.WriteTimeout = 10*time.Second, 60*time.Second, 60*time.Second
		s.ErrorLog = logger
		go func(s *http.Server) {
			logger.Printf("listening on %s", s.Addr)
			if err := s.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				logger.Fatal(err)
			}
		}(s)
	}

	go func() {
		t := time.NewTicker(cfg.ScanInterval)
		defer t.Stop()
		for {
			cctx, cancel := context.WithTimeout(ctx, cfg.ScanInterval)
			v := a.Cycle(cctx)
			cancel()
			logger.Printf("cycle: %d items, %d untrusted, %d errors", len(v.Items), len(v.Untrusted), len(v.Errors))
			select {
			case <-ctx.Done():
				return
			case <-t.C:
			}
		}
	}()

	<-ctx.Done()
	shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	for _, s := range servers {
		_ = s.Shutdown(shutdown)
	}
	if err := st.Save(); err != nil {
		logger.Print(err)
	}
}
