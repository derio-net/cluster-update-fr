package session

import (
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/derio-net/cluster-update-fr/internal/kube"
	"github.com/derio-net/cluster-update-fr/internal/store"
)

func TestNamesAreDeterministicAndValid(t *testing.T) {
	ids := []string{"pr-7", "frank-os-talos-1.13.4", "hop-os-k8s-1.35.0", "pr-" + strings.Repeat("9", 80), "Weird_ID.x"}
	seen := map[string]bool{}
	for _, id := range ids {
		n := PodName(id)
		if n != PodName(id) {
			t.Fatalf("PodName(%q) not deterministic", id)
		}
		if !kube.ValidName(n, 63) || !kube.ValidName(SecretName(id), 253) || !kube.ValidName(BriefName(id), 253) {
			t.Errorf("invalid names for %q: %s %s", id, n, SecretName(id))
		}
		if seen[n] {
			t.Errorf("collision on %s", n)
		}
		seen[n] = true
	}
	if PodName("pr-7") == PodName("pr-8") {
		t.Error("different upgrades must not share a pod")
	}
}

func TestUpgradeIDMustBeALabelValue(t *testing.T) {
	for _, bad := range []string{"", "has space", strings.Repeat("a", 64), "-lead", "a/b"} {
		if err := ValidUpgradeID(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	if err := ValidUpgradeID("frank-os-talos-1.13.4"); err != nil {
		t.Error(err)
	}
}

func TestTargets(t *testing.T) {
	if Target(TypeFrankOS, "frank", "") != "os:frank" || Target(TypeHopOS, "hop", "") != "os:hop" {
		t.Error("os targets")
	}
	if Target(TypeStateful, "frank", "paperclip-db") != "app:frank/paperclip-db" {
		t.Error("app target")
	}
}

func newStore(t *testing.T) *store.Store {
	t.Helper()
	s, err := store.Open(t.TempDir(), func() time.Time { return time.Unix(0, 0) })
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestLocks(t *testing.T) {
	s := newStore(t)
	l := Locks{Store: s}
	if err := l.Acquire("os:frank", "frank-os-a"); err != nil {
		t.Fatal(err)
	}
	if err := l.Acquire("os:frank", "frank-os-a"); err != nil {
		t.Errorf("the holder re-acquiring is idempotent: %v", err)
	}
	err := l.Acquire("os:frank", "frank-os-b")
	var le *LockedError
	if !errors.As(err, &le) || le.Holder != "frank-os-a" {
		t.Fatalf("second upgrade on the same target: %v", err)
	}
	if err := l.Acquire("os:hop", "hop-os-a"); err != nil {
		t.Errorf("different target: %v", err)
	}
	// Survives a reload.
	if err := s.Save(); err != nil {
		t.Fatal(err)
	}
	l.Release("os:frank", "frank-os-b") // not the holder: no-op
	if h := l.Holder("os:frank"); h != "frank-os-a" {
		t.Errorf("holder = %q", h)
	}
	l.Release("os:frank", "frank-os-a")
	if err := l.Acquire("os:frank", "frank-os-b"); err != nil {
		t.Errorf("after release: %v", err)
	}
}

func TestLockIsExclusiveUnderConcurrency(t *testing.T) {
	l := Locks{Store: newStore(t)}
	var wg sync.WaitGroup
	var mu sync.Mutex
	winners := map[string]bool{}
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			id := "pr-" + string(rune('a'+i%26)) + string(rune('a'+i/26))
			if l.Acquire("app:frank/litellm", id) == nil {
				mu.Lock()
				winners[id] = true
				mu.Unlock()
			}
		}(i)
	}
	wg.Wait()
	if len(winners) != 1 {
		t.Fatalf("winners = %v", winners)
	}
}
