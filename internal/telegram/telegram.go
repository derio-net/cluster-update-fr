// Package telegram posts to the derio.net group's #security topic — and only
// there: the group is shared with other bots, so every message carries the
// topic's message_thread_id, and without one the bot does not post at all.
// parse_mode is pinned to HTML (an unset parse_mode is NOT plain text —
// frank's Grafana/Telegram gotcha); callers escape every value.
package telegram

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"

	"github.com/derio-net/cluster-update-fr/internal/config"
	"github.com/derio-net/cluster-update-fr/internal/scrub"
)

// ErrUnconfigured means token, chat id or thread id is missing.
var ErrUnconfigured = errors.New("telegram: not configured (bot token, chat id and #security thread id are all required)")

// Client sends messages.
type Client struct {
	API  string // default https://api.telegram.org
	Cfg  config.Telegram
	HTTP *http.Client
}

// Send posts text (HTML) to the #security topic.
func (c *Client) Send(ctx context.Context, text string) error {
	if !c.Cfg.Configured() {
		return ErrUnconfigured
	}
	scrub.Register("telegram-bot-token", c.Cfg.BotToken)
	thread, err := strconv.Atoi(c.Cfg.ThreadID)
	if err != nil {
		return fmt.Errorf("telegram: thread id %q is not a number", c.Cfg.ThreadID)
	}
	body, _ := json.Marshal(map[string]any{
		"chat_id":                  c.Cfg.ChatID, // a string: supergroup ids are negative
		"message_thread_id":        thread,
		"text":                     scrub.String(text),
		"parse_mode":               "HTML",
		"disable_web_page_preview": true,
	})
	api := c.API
	if api == "" {
		api = "https://api.telegram.org"
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, api+"/bot"+c.Cfg.BotToken+"/sendMessage", bytes.NewReader(body))
	if err != nil {
		return errors.New("telegram: cannot build request")
	}
	req.Header.Set("Content-Type", "application/json")
	hc := c.HTTP
	if hc == nil {
		hc = http.DefaultClient
	}
	resp, err := hc.Do(req)
	if err != nil {
		// net/http errors quote the URL, which carries the token.
		return fmt.Errorf("telegram: send failed: %s", scrub.String(err.Error()))
	}
	defer resp.Body.Close()
	var out struct {
		OK          bool   `json:"ok"`
		Description string `json:"description"`
	}
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	_ = json.Unmarshal(b, &out)
	if resp.StatusCode != http.StatusOK || !out.OK {
		return fmt.Errorf("telegram: %d %s", resp.StatusCode, scrub.String(out.Description))
	}
	return nil
}
