package app

import (
	"context"
	"encoding/json"

	"github.com/derio-net/cluster-update-fr/internal/store"
)

// The Telegram outbox (format: store.OutboxState). Every writer updates it
// atomically under the store lock — the launcher even queues its alarms in
// the same update as their de-dup key — so concurrent writers never lose
// each other's messages. Sending happens outside the store lock, serialised
// by outboxMu, and removes exactly what it sent.

func (a *App) updateOutbox(fn func(*store.OutboxState)) {
	_ = a.Store.UpdateBlob(store.OutboxBlob, func(cur json.RawMessage) (json.RawMessage, error) {
		st := store.LoadOutbox(cur)
		fn(&st)
		return json.Marshal(st)
	})
}

// enqueue adds messages to the outbox atomically, enforcing the cap.
func (a *App) enqueue(security bool, texts ...string) {
	if len(texts) == 0 {
		return
	}
	a.updateOutbox(func(st *store.OutboxState) { st.Append(security, texts...) })
}

// flushOutbox sends what is queued, oldest first, and removes what was sent.
func (a *App) flushOutbox(ctx context.Context) {
	a.outboxMu.Lock()
	defer a.outboxMu.Unlock()
	var snapshot []store.OutboxMsg
	a.updateOutbox(func(st *store.OutboxState) { snapshot = append(snapshot, st.Msgs...) })
	sent := map[int64]bool{}
	for _, m := range snapshot {
		if err := a.sendErr(ctx, m.Text); err != nil {
			break // keep order; retry next cycle
		}
		sent[m.ID] = true
	}
	if len(sent) == 0 {
		return
	}
	a.updateOutbox(func(st *store.OutboxState) {
		var keep []store.OutboxMsg
		for _, m := range st.Msgs {
			if !sent[m.ID] {
				keep = append(keep, m)
			}
		}
		st.Msgs = keep
	})
}

// outboxLen reports how many messages wait (tests, metrics).
func (a *App) outboxLen() int {
	var n int
	a.updateOutbox(func(st *store.OutboxState) { n = len(st.Msgs) })
	return n
}
