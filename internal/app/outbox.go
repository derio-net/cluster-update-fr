package app

import (
	"context"
	"encoding/json"
	"fmt"
)

// The Telegram outbox holds messages for #security that could not be sent
// yet. Every writer goes through the store's atomic UpdateJSON (under the
// store lock, in the single process that holds the state flock), so
// concurrent writers — the cycle's vulnerability alarms and a session start's
// security alarm — never lose each other's messages. Sending happens outside
// the store lock, serialised by outboxMu, and removes exactly what it sent.

// outboxCap bounds the outbox. At the cap the oldest NON-security message is
// dropped first; when only security alarms remain, the oldest of them are
// collapsed into ONE "N alarms pending" message — a security alarm is never
// silently lost.
const outboxCap = 50

type outboxMsg struct {
	ID       int64  `json:"id"`
	Text     string `json:"text"`
	Security bool   `json:"security"`
	Folded   int    `json:"folded,omitempty"` // >0: a collapse of this many security alarms
}

type outboxState struct {
	Next int64       `json:"next"`
	Msgs []outboxMsg `json:"msgs"`
}

// loadOutbox decodes the blob, accepting the earlier []string shape.
func loadOutbox(raw json.RawMessage) outboxState {
	var st outboxState
	if len(raw) == 0 {
		return st
	}
	if json.Unmarshal(raw, &st) == nil {
		return st
	}
	var old []string
	if json.Unmarshal(raw, &old) == nil {
		for _, t := range old {
			st.Next++
			st.Msgs = append(st.Msgs, outboxMsg{ID: st.Next, Text: t, Security: true})
		}
	}
	return st
}

func (a *App) updateOutbox(fn func(*outboxState)) {
	_ = a.Store.UpdateBlob(blobOutbox, func(cur json.RawMessage) (json.RawMessage, error) {
		st := loadOutbox(cur)
		fn(&st)
		return json.Marshal(st)
	})
}

// enqueue adds messages to the outbox atomically, enforcing the cap.
func (a *App) enqueue(security bool, texts ...string) {
	if len(texts) == 0 {
		return
	}
	a.updateOutbox(func(st *outboxState) {
		for _, t := range texts {
			st.Next++
			st.Msgs = append(st.Msgs, outboxMsg{ID: st.Next, Text: t, Security: security})
		}
		enforceCap(st)
	})
}

func enforceCap(st *outboxState) {
	for len(st.Msgs) > outboxCap {
		dropped := false
		for i, m := range st.Msgs {
			if !m.Security {
				st.Msgs = append(st.Msgs[:i], st.Msgs[i+1:]...)
				dropped = true
				break
			}
		}
		if dropped {
			continue
		}
		// Only security alarms left: fold the oldest ones into a single
		// pending-count message that stays at the front.
		excess := len(st.Msgs) - outboxCap + 1
		folded := 0
		var keep []outboxMsg
		for i, m := range st.Msgs {
			if i < excess {
				if m.Folded > 0 {
					folded += m.Folded
				} else {
					folded++
				}
				continue
			}
			keep = append(keep, m)
		}
		st.Next++
		summary := outboxMsg{ID: st.Next, Security: true, Folded: folded,
			Text: fmt.Sprintf("🚨 <b>%d security alarms pending</b> could not be delivered individually — see the update console.", folded)}
		st.Msgs = append([]outboxMsg{summary}, keep...)
	}
}

// flushOutbox sends what is queued, oldest first, and removes what was sent.
func (a *App) flushOutbox(ctx context.Context) {
	a.outboxMu.Lock()
	defer a.outboxMu.Unlock()
	var snapshot []outboxMsg
	a.updateOutbox(func(st *outboxState) { snapshot = append(snapshot, st.Msgs...) })
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
	a.updateOutbox(func(st *outboxState) {
		var keep []outboxMsg
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
	a.updateOutbox(func(st *outboxState) { n = len(st.Msgs) })
	return n
}
