// Package session launches and ends disposable upgrade-session pods
// (R20–R23, R29). A session's identity is its upgrade id — never a random
// suffix — so a second Start finds the running pod and attaches to it;
// a lock per target (one per cluster OS, one per application) refuses a
// second session that would change the same thing, naming the holder. The
// server-side lock is the guarantee; the disabled button is only courtesy.
package session

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/derio-net/cluster-update-fr/internal/kube"
	"github.com/derio-net/cluster-update-fr/internal/store"
)

// Upgrade types (the cluster-update.fr/type label values frank's network
// policies select on).
const (
	TypeChartMajor = "chart-major"
	TypeStateful   = "stateful"
	TypeRollouts   = "rollouts"
	TypeFrankOS    = "frank-os"
	TypeHopOS      = "hop-os"
)

// Types lists every type.
var Types = []string{TypeChartMajor, TypeStateful, TypeRollouts, TypeFrankOS, TypeHopOS}

// Labels.
const (
	LabelRunID = "fr.run/id"
	LabelType  = "cluster-update.fr/type"
)

var labelValue = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9._-]*[A-Za-z0-9])?$`)

// ValidUpgradeID: the id is the fr.run/id label value runs-fr selects on.
func ValidUpgradeID(id string) error {
	if len(id) == 0 || len(id) > 63 || !labelValue.MatchString(id) {
		return fmt.Errorf("session: upgrade id %q is not a valid label value", id)
	}
	return nil
}

var nonDNS = regexp.MustCompile(`[^a-z0-9-]+`)

// PodName derives the pod name from the upgrade id alone: a sanitised prefix
// plus a short hash of the full id (so sanitising cannot collide).
func PodName(upgradeID string) string {
	sum := sha256.Sum256([]byte(upgradeID))
	base := nonDNS.ReplaceAllString(strings.ToLower(upgradeID), "-")
	base = strings.Trim(base, "-")
	if len(base) > 40 {
		base = strings.Trim(base[:40], "-")
	}
	if base == "" {
		base = "x"
	}
	return kube.SessionPrefix + base + "-" + hex.EncodeToString(sum[:])[:8]
}

// SecretName is the per-session credentials Secret.
func SecretName(upgradeID string) string { return PodName(upgradeID) + "-creds" }

// BriefName is the per-session brief Secret.
func BriefName(upgradeID string) string { return PodName(upgradeID) + "-brief" }

// Target is what a session changes: a cluster's OS or one application.
func Target(typ, cluster, app string) string {
	if typ == TypeFrankOS || typ == TypeHopOS {
		return "os:" + cluster
	}
	return "app:" + cluster + "/" + app
}

// LockedError names the session holding a target.
type LockedError struct{ Target, Holder string }

func (e *LockedError) Error() string {
	return fmt.Sprintf("session: %s is being changed by session %s; end it first", e.Target, e.Holder)
}

const lockBlob = "session-locks"

// Locks are per-target session locks persisted in the store.
type Locks struct{ Store *store.Store }

// Acquire takes target for upgradeID. Re-acquiring by the holder succeeds.
func (l Locks) Acquire(target, upgradeID string) error {
	return l.Store.UpdateBlob(lockBlob, func(cur json.RawMessage) (json.RawMessage, error) {
		m := map[string]string{}
		if len(cur) > 0 {
			if err := json.Unmarshal(cur, &m); err != nil {
				return nil, errors.New("session: lock table unreadable")
			}
		}
		if h, ok := m[target]; ok && h != upgradeID {
			return nil, &LockedError{Target: target, Holder: h}
		}
		m[target] = upgradeID
		return json.Marshal(m)
	})
}

// Release frees target if upgradeID holds it.
func (l Locks) Release(target, upgradeID string) {
	_ = l.Store.UpdateBlob(lockBlob, func(cur json.RawMessage) (json.RawMessage, error) {
		m := map[string]string{}
		_ = json.Unmarshal(cur, &m)
		if m[target] == upgradeID {
			delete(m, target)
		}
		return json.Marshal(m)
	})
}

// Holder returns who holds target ("" if free).
func (l Locks) Holder(target string) string {
	m := map[string]string{}
	l.Store.GetBlob(lockBlob, &m)
	return m[target]
}
