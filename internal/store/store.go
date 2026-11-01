// Package store is the console's state: every update and its lifecycle
// (R15, R16, R26), History, the engine's ledger (holds, approvals, CI
// retries) and opaque blobs other packages persist (alarm records, session
// locks). One JSON file on the PVC, written atomically (temp + rename); a
// corrupt file is moved aside and the console starts empty with a warning,
// never a crash.
package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/derio-net/cluster-update-fr/internal/engine"
	"github.com/derio-net/cluster-update-fr/internal/live"
	"github.com/derio-net/cluster-update-fr/internal/scrub"
)

// State is an update's lifecycle state. The single enum used by the store,
// the metrics and the UI.
type State string

// States: pending → approved → merged → applied → verified, or failed,
// rolled-back, held, abandoned.
const (
	Pending    State = "pending"
	Approved   State = "approved"
	Merged     State = "merged"
	Applied    State = "applied"
	Verified   State = "verified"
	Failed     State = "failed"
	RolledBack State = "rolled-back"
	Held       State = "held"
	Abandoned  State = "abandoned"
)

// AllStates lists every state, in display order.
var AllStates = []State{Pending, Approved, Held, Merged, Applied, Verified, Failed, RolledBack, Abandoned}

// Label is the console's wording; merged and applied are "rolled out,
// unverified" until verification passes (R16).
func (s State) Label() string {
	switch s {
	case Merged:
		return "merged, not yet applied"
	case Applied:
		return "rolled out, unverified"
	}
	return string(s)
}

// Terminal reports a state nothing leaves.
func (s State) Terminal() bool { return s == Verified || s == RolledBack || s == Abandoned }

var legal = map[State][]State{
	Pending:  {Approved, Held, Merged, Failed, Abandoned},
	Approved: {Merged, Held, Failed, Abandoned, Pending},
	Held:     {Pending, Approved, Abandoned, Failed},
	Merged:   {Applied, Failed, RolledBack},
	Applied:  {Verified, Failed, RolledBack},
	Failed:   {RolledBack, Abandoned, Pending, Merged},
	Verified: {RolledBack},
}

// Errors.
var (
	ErrIllegal     = errors.New("store: illegal state transition")
	ErrUnknown     = errors.New("store: no such update")
	ErrNeedsReason = errors.New("store: a failure state needs a named reason")
)

// Update is one update's record.
type Update struct {
	ID           string    `json:"id"`
	Title        string    `json:"title"`
	Cluster      string    `json:"cluster,omitempty"`
	Apps         []string  `json:"apps,omitempty"`
	Kind         string    `json:"kind,omitempty"` // image | chart | talos | kubernetes | omni | batch
	Name         string    `json:"name,omitempty"`
	From         string    `json:"from,omitempty"`
	To           string    `json:"to,omitempty"`
	Path         string    `json:"path,omitempty"`
	PR           int       `json:"pr,omitempty"`
	MergeSHA     string    `json:"merge_sha,omitempty"`
	Approver     string    `json:"approver,omitempty"`
	State        State     `json:"state"`
	Reason       string    `json:"reason,omitempty"`
	Since        time.Time `json:"since"`
	Rollout      string    `json:"rollout,omitempty"`
	Verification string    `json:"verification,omitempty"`
	Rollback     string    `json:"rollback,omitempty"`
	Session      string    `json:"session,omitempty"`
	Transcript   string    `json:"transcript,omitempty"` // scrubbed
	// Members (a batch) are the item ids it carries; ShippedIn (a member)
	// is the batch PR that took it to main (c1c-r3).
	Members   []string `json:"members,omitempty"`
	ShippedIn int      `json:"shipped_in,omitempty"`
	// RevertPR is the console's open revert PR; RevertSHA its merge commit
	// once merged. Rolled back = revert merged AND verified (c1c-r12).
	RevertPR  int    `json:"revert_pr,omitempty"`
	RevertSHA string `json:"revert_sha,omitempty"`
}

// Event is one History entry.
type Event struct {
	At           time.Time `json:"at"`
	Update       string    `json:"update"`
	Action       string    `json:"action"`
	From         State     `json:"from,omitempty"`
	To           State     `json:"to,omitempty"`
	By           string    `json:"by,omitempty"`
	Reason       string    `json:"reason,omitempty"`
	PR           int       `json:"pr,omitempty"`
	SHA          string    `json:"sha,omitempty"`
	Rollout      string    `json:"rollout,omitempty"`
	Verification string    `json:"verification,omitempty"`
}

type data struct {
	Updates   map[string]*Update         `json:"updates"`
	History   []Event                    `json:"history"`
	Holds     map[string]string          `json:"holds"`
	Approvals map[string]string          `json:"approvals"`
	Retries   map[string]int             `json:"retries"`
	RetriedAt map[string]time.Time       `json:"retried_at,omitempty"`
	Blobs     map[string]json.RawMessage `json:"blobs"`
}

// Store is safe for concurrent use.
type Store struct {
	mu      sync.Mutex
	path    string
	now     func() time.Time
	d       data
	lock    *os.File
	Warning string // set when the state file was unreadable at Open
}

// maxHistory bounds the history kept in the file.
const maxHistory = 5000

// ErrLocked means another process holds the state directory: the console is
// a single writer (one replica, Deployment strategy Recreate), and a second
// one must exit instead of racing the first one's writes.
var ErrLocked = errors.New("store: the state directory is held by another console process (single writer: replicas 1, strategy Recreate)")

// Open takes the state directory's exclusive lock (dir/state.lock, flock,
// non-blocking) and loads dir/state.json (or starts empty). Close releases
// the lock.
func Open(dir string, now func() time.Time) (*Store, error) {
	if now == nil {
		now = time.Now
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	lock, err := os.OpenFile(filepath.Join(dir, "state.lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		lock.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return nil, ErrLocked
		}
		return nil, fmt.Errorf("store: lock: %w", err)
	}
	s := &Store{path: filepath.Join(dir, "state.json"), now: now, lock: lock}
	s.d = empty()
	b, err := os.ReadFile(s.path)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return s, nil
	case err != nil:
		s.Close()
		return nil, err
	}
	var d data
	if err := json.Unmarshal(b, &d); err != nil {
		aside := fmt.Sprintf("%s.corrupt-%d", s.path, now().Unix())
		_ = os.Rename(s.path, aside)
		s.Warning = "state file was unreadable and was moved to " + filepath.Base(aside) + "; started empty"
		return s, nil
	}
	s.d = d
	s.fill()
	return s, nil
}

// Close releases the state directory lock. The store must not be used after.
func (s *Store) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.lock != nil {
		_ = syscall.Flock(int(s.lock.Fd()), syscall.LOCK_UN)
		_ = s.lock.Close()
		s.lock = nil
	}
}

func empty() data {
	return data{Updates: map[string]*Update{}, Holds: map[string]string{}, Approvals: map[string]string{}, Retries: map[string]int{}, Blobs: map[string]json.RawMessage{}}
}

func (s *Store) fill() {
	e := empty()
	if s.d.Updates == nil {
		s.d.Updates = e.Updates
	}
	if s.d.Holds == nil {
		s.d.Holds = e.Holds
	}
	if s.d.Approvals == nil {
		s.d.Approvals = e.Approvals
	}
	if s.d.Retries == nil {
		s.d.Retries = e.Retries
	}
	// Earlier state files keyed retries "id@sha"; fold them into the id.
	for k, n := range s.d.Retries {
		if id, _, ok := strings.Cut(k, "@"); ok {
			delete(s.d.Retries, k)
			s.d.Retries[id] += n
		}
	}
	if s.d.Blobs == nil {
		s.d.Blobs = e.Blobs
	}
}

// Save writes the state atomically.
func (s *Store) Save() error {
	s.mu.Lock()
	b, err := json.MarshalIndent(s.d, "", " ")
	s.mu.Unlock()
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(b); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return os.Rename(tmp, s.path)
}

// Track registers an update as pending if it is not known yet; known
// updates keep their state but refresh descriptive fields.
func (s *Store) Track(u Update) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if cur, ok := s.d.Updates[u.ID]; ok {
		if u.Title != "" {
			cur.Title = u.Title
		}
		if u.Rollback != "" {
			cur.Rollback = u.Rollback
		}
		if len(u.Apps) > 0 {
			cur.Apps = u.Apps
		}
		for _, f := range []struct {
			dst *string
			v   string
		}{{&cur.Kind, u.Kind}, {&cur.Cluster, u.Cluster}, {&cur.Name, u.Name}, {&cur.From, u.From}, {&cur.To, u.To}, {&cur.Path, u.Path}} {
			if *f.dst == "" && f.v != "" {
				*f.dst = f.v
			}
		}
		return
	}
	u.State, u.Since = Pending, s.now()
	cp := u
	s.d.Updates[u.ID] = &cp
}

// MarkMerged records a PR the console merged for an update outside the
// engine (a session PR): pending/approved/held move to merged; an update
// already merged (a later step's PR) takes the newer merge commit.
func (s *Store) MarkMerged(id, sha string, pr int, by, reason string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	u, ok := s.d.Updates[id]
	if !ok {
		return ErrUnknown
	}
	set := func(u *Update) {
		u.MergeSHA, u.PR = sha, pr
		if u.Approver == "" {
			u.Approver = by
		}
	}
	switch u.State {
	case Pending, Approved, Held:
		return s.transitionAs(id, Merged, by, reason, set, u.State == Held)
	case Merged, Applied, Failed:
		// a later PR of the same session: verification restarts from it
		return s.transitionAs(id, Merged, by, reason, set, true)
	}
	// Terminal (verified, rolled back, abandoned): never rewrite its merge
	// commit under a state that claims it is settled (sec2-6). The caller
	// refuses before merging; this is the second layer.
	s.appendEvent(Event{At: s.now(), Update: id, Action: "merge-recorded-elsewhere", By: by, PR: pr, SHA: sha,
		Reason: fmt.Sprintf("PR #%d merged while the update was %s; its record was left unchanged", pr, u.State)})
	return fmt.Errorf("%w: %s is %s; a merge cannot be recorded on it", ErrIllegal, id, u.State)
}

// MarkRevertMerged records that the update's revert PR merged at sha; the
// verifier moves it to rolled-back once that commit is applied and verified.
func (s *Store) MarkRevertMerged(id, sha, by string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	u, ok := s.d.Updates[id]
	if !ok {
		return ErrUnknown
	}
	u.RevertSHA = sha
	s.appendEvent(Event{At: s.now(), Update: id, Action: "revert-merged", By: by, PR: u.RevertPR, SHA: sha, Reason: fmt.Sprintf("revert PR #%d merged; rolled back once verified", u.RevertPR)})
	return nil
}

// Reopen moves an ABANDONED update back to pending (a new session for an
// update an earlier session ended without merging). Other states: no-op.
func (s *Store) Reopen(id, by, reason string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	u, ok := s.d.Updates[id]
	if !ok || u.State != Abandoned {
		return nil
	}
	return s.transitionAs(id, Pending, by, reason, nil, true)
}

// Get returns a copy of an update.
func (s *Store) Get(id string) (Update, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	u, ok := s.d.Updates[id]
	if !ok {
		return Update{}, false
	}
	return *u, true
}

// Updates returns copies of every update, newest state change first.
func (s *Store) Updates() []Update {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Update, 0, len(s.d.Updates))
	for _, u := range s.d.Updates {
		out = append(out, *u)
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].Since.Equal(out[j].Since) {
			return out[i].Since.After(out[j].Since)
		}
		return out[i].ID < out[j].ID
	})
	return out
}

// Transition moves an update to state to; with (optional) edits the record
// first. Failure states need a reason.
func (s *Store) Transition(id string, to State, by, reason string, with func(*Update)) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.transition(id, to, by, reason, with)
}

func (s *Store) transition(id string, to State, by, reason string, with func(*Update)) error {
	return s.transitionAs(id, to, by, reason, with, false)
}

// transitionAs is transition with an override for a recorded fact the
// state machine would otherwise refuse (the reconciler's held → merged).
func (s *Store) transitionAs(id string, to State, by, reason string, with func(*Update), force bool) error {
	u, ok := s.d.Updates[id]
	if !ok {
		return ErrUnknown
	}
	if (to == Failed || to == Abandoned || to == RolledBack) && strings.TrimSpace(reason) == "" {
		return ErrNeedsReason
	}
	allowed := force
	for _, next := range legal[u.State] {
		if next == to {
			allowed = true
		}
	}
	if !allowed {
		return fmt.Errorf("%w: %s → %s", ErrIllegal, u.State, to)
	}
	if with != nil {
		with(u)
	}
	from := u.State
	u.State, u.Since, u.Reason = to, s.now(), scrub.String(reason)
	s.appendEvent(Event{At: s.now(), Update: id, Action: "state", From: from, To: to, By: by, Reason: u.Reason,
		PR: u.PR, SHA: u.MergeSHA, Rollout: u.Rollout, Verification: u.Verification})
	return nil
}

func (s *Store) appendEvent(e Event) {
	e.Reason = scrub.String(e.Reason)
	s.d.History = append(s.d.History, e)
	if n := len(s.d.History); n > maxHistory {
		s.d.History = s.d.History[n-maxHistory:]
	}
}

// AddEvent appends a free-form History entry (session start/end, cleanup).
func (s *Store) AddEvent(e Event) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if e.At.IsZero() {
		e.At = s.now()
	}
	s.appendEvent(e)
}

// History returns the events for update id ("" = all), newest first.
func (s *Store) History(id string) []Event {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []Event
	for i := len(s.d.History) - 1; i >= 0; i-- {
		if id == "" || s.d.History[i].Update == id {
			out = append(out, s.d.History[i])
		}
	}
	return out
}

// CountByState counts updates per state (every state present, zero or not).
func (s *Store) CountByState() map[State]int {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := map[State]int{}
	for _, st := range AllStates {
		out[st] = 0
	}
	for _, u := range s.d.Updates {
		out[u.State]++
	}
	return out
}

// --- engine.Ledger ---------------------------------------------------------

// Hold implements engine.Ledger.
func (s *Store) Hold(id string) (bool, string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	by, ok := s.d.Holds[id]
	return ok, by
}

// SetHold implements engine.Ledger.
func (s *Store) SetHold(id string, held bool, by string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if held {
		s.d.Holds[id] = by
	} else {
		delete(s.d.Holds, id)
	}
}

// Approved implements engine.Ledger.
func (s *Store) Approved(id string) (bool, string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	by, ok := s.d.Approvals[id]
	return ok, by
}

// SetApproved implements engine.Ledger.
func (s *Store) SetApproved(id, by string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.d.Approvals[id] = by
}

// Retries implements engine.Ledger: per update, whatever its head SHA.
func (s *Store) Retries(id string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.d.Retries[id]
}

// AddRetry implements engine.Ledger. The first one records WHEN the retry
// happened: only CI results newer than that count afterwards (c1c-r11).
func (s *Store) AddRetry(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.d.Retries[id] == 0 {
		if s.d.RetriedAt == nil {
			s.d.RetriedAt = map[string]time.Time{}
		}
		s.d.RetriedAt[id] = s.now()
	}
	s.d.Retries[id]++
}

// RetriedAt is when the update's one CI retry was made (zero if none).
func (s *Store) RetriedAt(id string) time.Time {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.d.RetriedAt[id]
}

// Record implements engine.Ledger: engine actions drive update states.
func (s *Store) Record(e engine.Event) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.d.Updates[e.Item]; !ok {
		kind := ""
		if strings.HasPrefix(e.Item, "batch-") {
			kind = "batch"
		}
		s.d.Updates[e.Item] = &Update{ID: e.Item, Title: e.Detail, Kind: kind, PR: e.PR, State: Pending, Since: s.now()}
	}
	u := s.d.Updates[e.Item]
	s.appendEvent(Event{At: e.At, Update: e.Item, Action: e.Action, By: e.By, Reason: e.Detail, PR: e.PR, SHA: e.SHA})
	switch e.Action {
	case "approved", "batch-approved":
		_ = s.transition(e.Item, Approved, e.By, "", func(u *Update) {
			u.Approver = e.By
			if len(e.Members) > 0 {
				u.Members, u.Kind = append([]string(nil), e.Members...), "batch"
			}
		})
	case "merged":
		_ = s.transition(e.Item, Merged, e.By, "", func(u *Update) {
			u.MergeSHA, u.PR = e.SHA, e.PR
			if u.Approver == "" {
				u.Approver = e.By
			}
		})
		s.shipMembers(e.Item)
	case "held":
		_ = s.transition(e.Item, Held, e.By, "held by "+e.By, nil)
	case "released":
		if u.State == Held {
			_ = s.transition(e.Item, Pending, e.By, "", nil)
		}
	case "failed-ci":
		_ = s.transition(e.Item, Failed, e.By, "failed — CI: "+e.Detail, nil)
	case "revert-opened":
		// Opening a revert rolls nothing back (c1c-r12): the update stays as
		// it is until the revert PR is merged AND verified.
		u.RevertPR, u.RevertSHA = e.PR, ""
	}
}

// shipMembers: a merged batch carries its members to main, so each member
// moves to merged with the batch's merge commit, "shipped in batch #N", and
// is verified on its own app and cluster (c1c-r3). Caller holds s.mu.
func (s *Store) shipMembers(batchID string) {
	b, ok := s.d.Updates[batchID]
	if !ok || b.State != Merged {
		return
	}
	for _, id := range b.Members {
		m, ok := s.d.Updates[id]
		if !ok || (m.State != Pending && m.State != Approved && m.State != Held) {
			continue
		}
		_ = s.transitionAs(id, Merged, b.Approver, fmt.Sprintf("shipped in batch #%d", b.PR), func(u *Update) {
			u.MergeSHA, u.ShippedIn = b.MergeSHA, b.PR
			if u.Approver == "" {
				u.Approver = b.Approver
			}
		}, m.State == Held)
	}
}

var _ engine.Ledger = (*Store)(nil)

// --- blobs ------------------------------------------------------------------

// GetBlob decodes the blob stored under key into out (false if absent).
func (s *Store) GetBlob(key string, out any) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	b, ok := s.d.Blobs[key]
	if !ok {
		return false
	}
	return json.Unmarshal(b, out) == nil
}

// PutBlob stores v under key.
func (s *Store) PutBlob(key string, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.d.Blobs[key] = b
	return nil
}

// Update mutates a blob atomically under the store lock: fn gets the current
// raw value (nil if absent) and returns the new one.
func (s *Store) UpdateBlob(key string, fn func(cur json.RawMessage) (json.RawMessage, error)) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	next, err := fn(s.d.Blobs[key])
	if err != nil {
		return err
	}
	s.d.Blobs[key] = next
	return nil
}

// UpdateJSON is UpdateBlob for a typed value: fn mutates the decoded value
// in place, atomically under the store lock (read-modify-write races between
// writers are impossible; the state flock makes this process the only one).
func UpdateJSON[T any](s *Store, key string, fn func(*T) error) error {
	return s.UpdateBlob(key, func(cur json.RawMessage) (json.RawMessage, error) {
		var v T
		if len(cur) > 0 {
			if err := json.Unmarshal(cur, &v); err != nil {
				return nil, fmt.Errorf("store: blob %s unreadable: %w", key, err)
			}
		}
		if err := fn(&v); err != nil {
			return nil, err
		}
		return json.Marshal(v)
	})
}

// --- reconciliation (R26) ---------------------------------------------------

// Cleanup kinds.
const (
	CleanupPod    = "delete-session-pod"
	CleanupBranch = "delete-batch-branch"
)

// Cleanup is a leftover the caller must remove.
type Cleanup struct {
	Kind, Target, Reason string
}

// ReconcileInput is what reconciliation compares against.
type ReconcileInput struct {
	OpenPRs       map[int]bool
	MergedPRs     map[int]string // number -> merge sha (closed AND merged)
	ClosedPRs     map[int]bool   // confirmed closed WITHOUT merging (read just now)
	SessionPods   []live.Pod     // pods in the session namespace
	StaleBranches []string       // cluster-update/batch-* branches with no open PR
	ApplyTimeout  time.Duration  // merged → applied
	VerifyTimeout time.Duration  // applied → verified
}

// Reconcile turns every leftover into a named state and lists what must be
// cleaned up: updates whose PR closed unmerged are abandoned, merged updates
// never applied (and applied ones never verified) fail with the reason
// named, session pods with no open update and batch branches with no open PR
// are listed for deletion. Every transition it could not make is returned
// (c1c-r4), never dropped.
func (s *Store) Reconcile(in ReconcileInput) ([]Cleanup, []error) {
	if in.ApplyTimeout == 0 {
		in.ApplyTimeout = 2 * time.Hour
	}
	if in.VerifyTimeout == 0 {
		in.VerifyTimeout = time.Hour
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	var out []Cleanup
	var errs []error
	try := func(id string, err error) {
		if err != nil {
			errs = append(errs, fmt.Errorf("reconcile %s: %w", id, err))
		}
	}
	// Batches first: a merged batch ships its members before their own
	// (closed by Renovate) PRs could read as "closed without merging".
	ids := make([]string, 0, len(s.d.Updates))
	for id, u := range s.d.Updates {
		if len(u.Members) > 0 {
			ids = append([]string{id}, ids...)
		} else {
			ids = append(ids, id)
		}
	}
	waitingInBatch := map[string]bool{}
	for _, id := range ids {
		u := s.d.Updates[id]
		switch u.State {
		case Pending, Approved, Held:
			if waitingInBatch[id] {
				continue // its batch PR is still open; it goes with the batch
			}
			if len(u.Members) > 0 && (u.PR == 0 || in.OpenPRs[u.PR]) {
				for _, m := range u.Members {
					waitingInBatch[m] = true
				}
			}
			if u.PR > 0 && !in.OpenPRs[u.PR] {
				if sha, ok := in.MergedPRs[u.PR]; ok {
					// The PR merged on GitHub even though the console held it
					// (a person, or a batch): the reconciler records the fact,
					// so held → merged is legal for it alone.
					try(id, s.transitionAs(id, Merged, "reconciler", "", func(u *Update) { u.MergeSHA = sha }, u.State == Held))
					s.shipMembers(id)
					continue
				}
				// Fail closed: abandoned only when GitHub confirmed the PR
				// closed unmerged, never because it is merely missing from a
				// (possibly failed or partial) open list.
				if in.ClosedPRs[u.PR] {
					try(id, s.transition(id, Abandoned, "reconciler", fmt.Sprintf("PR #%d closed without merging", u.PR), nil))
				}
			}
		case Merged:
			if now.Sub(u.Since) > in.ApplyTimeout {
				try(id, s.transition(id, Failed, "reconciler", fmt.Sprintf("merged but not applied after %s: ArgoCD's last sync operation never reached the merge commit — needs you", in.ApplyTimeout), nil))
			}
		case Applied:
			if now.Sub(u.Since) > in.VerifyTimeout {
				try(id, s.transition(id, Failed, "reconciler", fmt.Sprintf("applied but the smoke test did not pass within %s — needs you", in.VerifyTimeout), nil))
			}
		}
	}
	for _, p := range in.SessionPods {
		id := p.Labels["fr.run/id"]
		u, ok := s.d.Updates[id]
		// Only terminal or unknown ids: a FAILED update is being repaired,
		// often from this very session (c1c-r6).
		if !ok || u.State.Terminal() {
			out = append(out, Cleanup{Kind: CleanupPod, Target: p.Name, Reason: "no open update for session " + id})
		}
	}
	for _, b := range in.StaleBranches {
		out = append(out, Cleanup{Kind: CleanupBranch, Target: b, Reason: "console branch with no open PR"})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Target < out[j].Target })
	sort.Slice(errs, func(i, j int) bool { return errs[i].Error() < errs[j].Error() })
	return out, errs
}

// Edit mutates an update record in place (descriptive fields: transcript,
// session, rollback text). It never changes the state.
func (s *Store) Edit(id string, fn func(*Update)) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	u, ok := s.d.Updates[id]
	if !ok {
		return ErrUnknown
	}
	st := u.State
	fn(u)
	u.State = st
	return nil
}
