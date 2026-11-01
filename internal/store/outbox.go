package store

import (
	"encoding/json"
	"fmt"
)

// The Telegram outbox: messages for #security not sent yet. Its format
// lives here so that a writer can append to it in the SAME atomic update as
// other state (UpdateBlobs) — the launcher records an alarm's de-dup key
// and queues the alarm together, so neither can exist without the other
// (c1d-r7).

// OutboxBlob is the outbox's blob key.
const OutboxBlob = "alarm-outbox"

// OutboxCap bounds the outbox. At the cap the oldest NON-security message is
// dropped first; when only security alarms remain, the oldest are folded
// into ONE "N alarms pending" message — a security alarm is never lost.
const OutboxCap = 50

// OutboxMsg is one queued message.
type OutboxMsg struct {
	ID       int64  `json:"id"`
	Text     string `json:"text"`
	Security bool   `json:"security"`
	Folded   int    `json:"folded,omitempty"` // >0: a fold of this many security alarms
}

// OutboxState is the outbox blob.
type OutboxState struct {
	Next int64       `json:"next"`
	Msgs []OutboxMsg `json:"msgs"`
}

// LoadOutbox decodes the blob, accepting the earlier []string shape.
func LoadOutbox(raw json.RawMessage) OutboxState {
	var st OutboxState
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
			st.Msgs = append(st.Msgs, OutboxMsg{ID: st.Next, Text: t, Security: true})
		}
	}
	return st
}

// Append adds messages and enforces the cap.
func (st *OutboxState) Append(security bool, texts ...string) {
	for _, t := range texts {
		st.Next++
		st.Msgs = append(st.Msgs, OutboxMsg{ID: st.Next, Text: t, Security: security})
	}
	st.EnforceCap()
}

// EnforceCap applies OutboxCap.
func (st *OutboxState) EnforceCap() {
	for len(st.Msgs) > OutboxCap {
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
		excess := len(st.Msgs) - OutboxCap + 1
		folded := 0
		var keep []OutboxMsg
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
		summary := OutboxMsg{ID: st.Next, Security: true, Folded: folded,
			Text: fmt.Sprintf("🚨 <b>%d security alarms pending</b> could not be delivered individually — see the update console.", folded)}
		st.Msgs = append([]OutboxMsg{summary}, keep...)
	}
}

// UpdateBlobs mutates several blobs in ONE atomic step under the store
// lock: fn gets the current raw values (absent keys missing) and edits the
// map in place; nothing is written if fn fails.
func (s *Store) UpdateBlobs(keys []string, fn func(m map[string]json.RawMessage) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	m := map[string]json.RawMessage{}
	for _, k := range keys {
		if v, ok := s.d.Blobs[k]; ok {
			m[k] = append(json.RawMessage(nil), v...)
		}
	}
	if err := fn(m); err != nil {
		return err
	}
	for _, k := range keys {
		if v, ok := m[k]; ok {
			s.d.Blobs[k] = v
		}
	}
	return nil
}
