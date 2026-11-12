package telegram

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/derio-net/cluster-update-fr/internal/config"
)

func TestSendPostsToTheSecurityTopicWithExplicitParseMode(t *testing.T) {
	var got map[string]any
	var path string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path = r.URL.Path
		_ = json.NewDecoder(r.Body).Decode(&got)
		_, _ = w.Write([]byte(`{"ok":true,"result":{"message_id":5}}`))
	}))
	defer srv.Close()
	bot := "123456" + ":" + strings.Repeat("Bt_-x", 7)
	c := &Client{API: srv.URL, Cfg: config.Telegram{BotToken: bot, ChatID: "-1001234567890", ThreadID: "42"}, HTTP: srv.Client()}
	secret := "gh" + "s_" + strings.Repeat("Zz12", 9)
	if err := c.Send(context.Background(), "<b>hi</b> "+secret); err != nil {
		t.Fatal(err)
	}
	if path != "/bot"+bot+"/sendMessage" {
		t.Errorf("path = %s", path)
	}
	if got["chat_id"] != "-1001234567890" {
		t.Errorf("chat_id must stay a string (negative supergroup id): %#v", got["chat_id"])
	}
	if got["message_thread_id"] != float64(42) {
		t.Errorf("message_thread_id = %#v", got["message_thread_id"])
	}
	if got["parse_mode"] != "HTML" {
		t.Errorf("parse_mode must be set explicitly: %#v", got["parse_mode"])
	}
	if strings.Contains(got["text"].(string), secret) {
		t.Error("text must be scrubbed")
	}
}

func TestUnconfiguredDoesNotSend(t *testing.T) {
	c := &Client{Cfg: config.Telegram{BotToken: "x", ChatID: "-1"}} // no thread id
	if err := c.Send(context.Background(), "x"); !errors.Is(err, ErrUnconfigured) {
		t.Fatalf("err = %v", err)
	}
}

func TestErrorsNeverCarryTheToken(t *testing.T) {
	bot := "123456" + ":" + strings.Repeat("Bt_-x", 7)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(400)
		_, _ = w.Write([]byte(`{"ok":false,"description":"Bad Request: can't parse entities"}`))
	}))
	defer srv.Close()
	c := &Client{API: srv.URL, Cfg: config.Telegram{BotToken: bot, ChatID: "-1", ThreadID: "1"}, HTTP: srv.Client()}
	err := c.Send(context.Background(), "x")
	if err == nil || strings.Contains(err.Error(), bot) || !strings.Contains(err.Error(), "parse entities") {
		t.Fatalf("err = %v", err)
	}
	dead := &Client{API: "http://127.0.0.1:1", Cfg: c.Cfg}
	if err := dead.Send(context.Background(), "x"); err == nil || strings.Contains(err.Error(), bot) {
		t.Fatalf("transport error leaked the token: %v", err)
	}
}
