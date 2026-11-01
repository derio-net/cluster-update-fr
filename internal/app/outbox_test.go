package app

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/derio-net/cluster-update-fr/internal/store"
)

type downSender struct{}

func (downSender) Send(context.Context, string) error { return errors.New("telegram: 502") }

func outboxApp(t *testing.T) *App {
	t.Helper()
	st, err := store.Open(t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(st.Close)
	return &App{Store: st, Telegram: downSender{}}
}

// Concurrent writers (the cycle and a session start) lose nothing (run
// with -race).
func TestOutboxConcurrentWritersLoseNothing(t *testing.T) {
	a := outboxApp(t)
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			a.enqueue(true, fmt.Sprintf("alarm %d-a", i), fmt.Sprintf("alarm %d-b", i))
			a.flushOutbox(context.Background()) // fails: Telegram down
		}(i)
	}
	wg.Wait()
	if n := a.outboxLen(); n != 40 {
		t.Fatalf("outbox holds %d messages, want 40", n)
	}
}

// At the cap a non-security message goes first; security alarms are never
// dropped, only folded into one "N pending" message.
func TestOutboxCapNeverDropsSecurityAlarms(t *testing.T) {
	st := &store.OutboxState{}
	add := func(sec bool, n int) {
		for i := 0; i < n; i++ {
			st.Next++
			st.Msgs = append(st.Msgs, store.OutboxMsg{ID: st.Next, Text: fmt.Sprint(st.Next), Security: sec})
		}
	}
	add(false, 10)
	add(true, 45)
	st.EnforceCap()
	if len(st.Msgs) != store.OutboxCap {
		t.Fatalf("len = %d", len(st.Msgs))
	}
	sec := 0
	for _, m := range st.Msgs {
		if m.Security {
			sec++
		}
	}
	if sec != 45 {
		t.Fatalf("security alarms kept: %d, want all 45", sec)
	}
	add(true, 30)
	st.EnforceCap()
	total := 0
	for _, m := range st.Msgs {
		if !m.Security {
			t.Fatal("non-security message kept while security alarms were folded")
		}
		if m.Folded > 0 {
			total += m.Folded
			if !strings.Contains(m.Text, fmt.Sprintf("%d security alarms pending", m.Folded)) {
				t.Errorf("summary text = %q", m.Text)
			}
		} else {
			total++
		}
	}
	if len(st.Msgs) != store.OutboxCap || total != 75 {
		t.Fatalf("len %d, alarms accounted for %d, want %d / 75", len(st.Msgs), total, store.OutboxCap)
	}
}

// A message that cannot be sent stays; once Telegram is back it goes, once.
func TestOutboxFlushRemovesOnlyWhatWasSent(t *testing.T) {
	a := outboxApp(t)
	a.enqueue(true, "one", "two")
	a.flushOutbox(context.Background())
	if a.outboxLen() != 2 {
		t.Fatal("unsent messages were dropped")
	}
	tg := &fakeSender{}
	a.Telegram = tg
	a.flushOutbox(context.Background())
	a.flushOutbox(context.Background())
	if a.outboxLen() != 0 || len(tg.msgs) != 2 {
		t.Fatalf("outbox %d, sent %v", a.outboxLen(), tg.msgs)
	}
}
