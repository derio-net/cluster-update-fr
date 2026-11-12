package identity

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

var now = time.Date(2026, 10, 31, 10, 0, 0, 0, time.UTC)

const iss = "https://auth.cluster.derio.net/application/o/updates/"
const aud = "updates-client"

func enc(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func sign(t *testing.T, key *rsa.PrivateKey, kid string, claims map[string]any) string {
	t.Helper()
	h, _ := json.Marshal(map[string]string{"alg": "RS256", "kid": kid, "typ": "JWT"})
	c, _ := json.Marshal(claims)
	in := enc(h) + "." + enc(c)
	sum := sha256.Sum256([]byte(in))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	return in + "." + enc(sig)
}

func claimsFor(user string, groups ...string) map[string]any {
	return map[string]any{"iss": iss, "aud": aud, "exp": now.Add(5 * time.Minute).Unix(), "iat": now.Unix(), "preferred_username": user, "groups": groups}
}

func setup(t *testing.T) (*JWT, *rsa.PrivateKey, *int32) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	ec, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	var fetches int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&fetches, 1)
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{
			{"kty": "RSA", "kid": "k1", "n": enc(key.N.Bytes()), "e": enc(big.NewInt(int64(key.E)).Bytes())},
			{"kty": "EC", "kid": "e1", "crv": "P-256", "x": enc(ec.X.Bytes()), "y": enc(ec.Y.Bytes())},
		}})
	}))
	t.Cleanup(srv.Close)
	return &JWT{JWKSURL: srv.URL, Issuer: iss, Audience: aud, Group: "cluster-operators", HTTP: srv.Client(), Now: func() time.Time { return now }}, key, &fetches
}

func request(jwt, user string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	if jwt != "" {
		r.Header.Set(HeaderJWT, jwt)
	}
	if user != "" {
		r.Header.Set(HeaderUser, user)
	}
	return r
}

func TestValidTokenGivesUserAndGroups(t *testing.T) {
	v, key, _ := setup(t)
	id, err := v.Authenticate(request(sign(t, key, "k1", claimsFor("derio", "cluster-operators", "x")), "derio"))
	if err != nil || id.User != "derio" || !id.In("cluster-operators") {
		t.Fatalf("id = %+v err = %v", id, err)
	}
	// Plain header absent is fine; the token is the source.
	if _, err := v.Authenticate(request(sign(t, key, "k1", claimsFor("derio", "cluster-operators")), "")); err != nil {
		t.Fatal(err)
	}
}

func TestRejections(t *testing.T) {
	v, key, _ := setup(t)
	other, _ := rsa.GenerateKey(rand.Reader, 2048)
	expired := claimsFor("derio", "cluster-operators")
	expired["exp"] = now.Add(-10 * time.Minute).Unix()
	wrongIss := claimsFor("derio", "cluster-operators")
	wrongIss["iss"] = "https://evil/"
	wrongAud := claimsFor("derio", "cluster-operators")
	wrongAud["aud"] = []string{"other"}
	noneAlg := enc([]byte(`{"alg":"none","kid":"k1"}`)) + "." + enc([]byte(`{"preferred_username":"derio"}`)) + "."
	cases := []struct {
		name string
		r    *http.Request
		want error
	}{
		{"header without JWT", request("", "derio"), ErrUnauthenticated},
		{"forged signature", request(sign(t, other, "k1", claimsFor("derio", "cluster-operators")), ""), ErrUnauthenticated},
		{"unknown key id", request(sign(t, key, "nope", claimsFor("derio", "cluster-operators")), ""), ErrUnauthenticated},
		{"expired", request(sign(t, key, "k1", expired), ""), ErrUnauthenticated},
		{"wrong issuer", request(sign(t, key, "k1", wrongIss), ""), ErrUnauthenticated},
		{"wrong audience", request(sign(t, key, "k1", wrongAud), ""), ErrUnauthenticated},
		{"alg none", request(noneAlg, ""), ErrUnauthenticated},
		{"garbage", request("a.b", ""), ErrUnauthenticated},
		{"wrong group", request(sign(t, key, "k1", claimsFor("derio", "users")), ""), ErrForbidden},
		{"header mismatch", request(sign(t, key, "k1", claimsFor("derio", "cluster-operators")), "admin"), ErrUnauthenticated},
	}
	for _, c := range cases {
		if _, err := v.Authenticate(c.r); !errors.Is(err, c.want) {
			t.Errorf("%s: err = %v, want %v", c.name, err, c.want)
		}
	}
}

func TestUnknownKidRefetchIsRateLimited(t *testing.T) {
	v, key, fetches := setup(t)
	for i := 0; i < 5; i++ {
		_, _ = v.Authenticate(request(sign(t, key, "unknown", claimsFor("derio", "cluster-operators")), ""))
	}
	if n := atomic.LoadInt32(fetches); n != 1 {
		t.Errorf("JWKS fetched %d times for unknown kids within a minute", n)
	}
}

func TestProxySecretMode(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "secret")
	secret := strings.Repeat("s3cr3t-", 6)
	_ = os.WriteFile(f, []byte(secret+"\n"), 0o600)
	p := ProxySecret{SecretFile: f, Group: "cluster-operators"}
	r := request("", "derio")
	r.Header.Set(HeaderSecret, secret)
	r.Header.Set(HeaderGroups, "users|cluster-operators")
	if id, err := p.Authenticate(r); err != nil || id.User != "derio" {
		t.Fatalf("id=%+v err=%v", id, err)
	}
	r.Header.Set(HeaderSecret, "wrong")
	if _, err := p.Authenticate(r); !errors.Is(err, ErrUnauthenticated) {
		t.Errorf("wrong secret: %v", err)
	}
	r.Header.Set(HeaderSecret, secret)
	r.Header.Set(HeaderGroups, "users")
	if _, err := p.Authenticate(r); !errors.Is(err, ErrForbidden) {
		t.Errorf("wrong group: %v", err)
	}
	if _, err := (ProxySecret{SecretFile: filepath.Join(dir, "missing"), Group: "g"}).Authenticate(r); !errors.Is(err, ErrNotConfigured) {
		t.Errorf("missing secret file must fail closed: %v", err)
	}
	if _, err := (Refuse{}).Authenticate(r); !errors.Is(err, ErrNotConfigured) {
		t.Error("refuse")
	}
}
