// Package identity verifies who is using the console. The bare
// X-authentik-username header is never trusted on its own:
//
//   - JWT mode (preferred): Authentik's proxy provider sends X-authentik-jwt,
//     signed with the provider's key. The console verifies the signature
//     against the provider's JWKS (RS256 or ES256 only; keys cached and
//     refetched at most once a minute for an unknown kid), the issuer, the
//     audience and the expiry, and takes the username AND groups from the
//     verified claims. A plain username header that disagrees is rejected.
//   - Proxy-secret mode (fallback, when the JWT cannot reach the console on
//     the forward-auth path): Traefik injects a shared secret header read
//     from a mounted Secret; it is compared in constant time, and only then
//     are Authentik's username and groups headers believed.
//
// Either way the operator must be in the configured group. With neither
// mode configured, every request is refused (fail closed).
package identity

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// Identity is a verified user.
type Identity struct {
	User   string
	Groups []string
}

// In reports group membership.
func (i Identity) In(group string) bool {
	for _, g := range i.Groups {
		if g == group {
			return true
		}
	}
	return false
}

// Authenticator verifies a request.
type Authenticator interface {
	Authenticate(r *http.Request) (Identity, error)
}

// Headers.
const (
	HeaderUser   = "X-authentik-username"
	HeaderGroups = "X-authentik-groups"
	HeaderJWT    = "X-authentik-jwt"
	HeaderSecret = "X-Cluster-Update-Proxy-Secret"
)

// IdentityHeaders are stripped from every request after verification so no
// handler can read an unverified copy.
var IdentityHeaders = []string{HeaderUser, HeaderGroups, HeaderJWT, HeaderSecret, "X-authentik-email", "X-authentik-name", "X-authentik-uid", "X-Forwarded-User"}

// Errors.
var (
	ErrUnauthenticated = errors.New("identity: not authenticated")
	ErrForbidden       = errors.New("identity: not in the operator group")
	ErrNotConfigured   = errors.New("identity: no verification configured; refusing all requests")
)

// Refuse is the fail-closed authenticator.
type Refuse struct{}

// Authenticate always fails.
func (Refuse) Authenticate(*http.Request) (Identity, error) { return Identity{}, ErrNotConfigured }

// ---------------------------------------------------------------- JWT mode

// JWT verifies Authentik's signed identity header.
type JWT struct {
	JWKSURL  string
	Issuer   string
	Audience string
	Group    string
	HTTP     *http.Client
	Now      func() time.Time

	mu      sync.Mutex
	keys    map[string]crypto.PublicKey
	fetched time.Time
}

const leeway = 60 * time.Second

func (v *JWT) now() time.Time {
	if v.Now == nil {
		return time.Now()
	}
	return v.Now()
}

// Authenticate verifies the JWT and the group, and cross-checks the plain
// username header.
func (v *JWT) Authenticate(r *http.Request) (Identity, error) {
	tok := strings.TrimSpace(r.Header.Get(HeaderJWT))
	if tok == "" {
		return Identity{}, fmt.Errorf("%w: no %s", ErrUnauthenticated, HeaderJWT)
	}
	id, err := v.Verify(r.Context(), tok)
	if err != nil {
		return Identity{}, err
	}
	if plain := r.Header.Get(HeaderUser); plain != "" && plain != id.User {
		return Identity{}, fmt.Errorf("%w: %s disagrees with the verified token", ErrUnauthenticated, HeaderUser)
	}
	if v.Group == "" || !id.In(v.Group) {
		return Identity{}, ErrForbidden
	}
	return id, nil
}

type header struct {
	Alg string `json:"alg"`
	Kid string `json:"kid"`
}

type claims struct {
	Iss      string          `json:"iss"`
	Aud      json.RawMessage `json:"aud"`
	Exp      int64           `json:"exp"`
	Nbf      int64           `json:"nbf"`
	Iat      int64           `json:"iat"`
	Username string          `json:"preferred_username"`
	Groups   []string        `json:"groups"`
}

func b64(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(strings.TrimRight(s, "="))
}

// Verify checks signature, issuer, audience and time; it returns the
// identity carried by the claims.
func (v *JWT) Verify(ctx context.Context, tok string) (Identity, error) {
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		return Identity{}, fmt.Errorf("%w: malformed token", ErrUnauthenticated)
	}
	hb, err := b64(parts[0])
	if err != nil {
		return Identity{}, fmt.Errorf("%w: malformed header", ErrUnauthenticated)
	}
	var h header
	if err := json.Unmarshal(hb, &h); err != nil {
		return Identity{}, fmt.Errorf("%w: malformed header", ErrUnauthenticated)
	}
	if h.Alg != "RS256" && h.Alg != "ES256" {
		return Identity{}, fmt.Errorf("%w: algorithm %q not accepted", ErrUnauthenticated, h.Alg)
	}
	key, err := v.key(ctx, h.Kid)
	if err != nil {
		return Identity{}, err
	}
	sig, err := b64(parts[2])
	if err != nil {
		return Identity{}, fmt.Errorf("%w: malformed signature", ErrUnauthenticated)
	}
	sum := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	switch k := key.(type) {
	case *rsa.PublicKey:
		if h.Alg != "RS256" || rsa.VerifyPKCS1v15(k, crypto.SHA256, sum[:], sig) != nil {
			return Identity{}, fmt.Errorf("%w: bad signature", ErrUnauthenticated)
		}
	case *ecdsa.PublicKey:
		if h.Alg != "ES256" || len(sig) != 64 ||
			!ecdsa.Verify(k, sum[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])) {
			return Identity{}, fmt.Errorf("%w: bad signature", ErrUnauthenticated)
		}
	default:
		return Identity{}, fmt.Errorf("%w: unsupported key", ErrUnauthenticated)
	}
	cb, err := b64(parts[1])
	if err != nil {
		return Identity{}, fmt.Errorf("%w: malformed claims", ErrUnauthenticated)
	}
	var c claims
	if err := json.Unmarshal(cb, &c); err != nil {
		return Identity{}, fmt.Errorf("%w: malformed claims", ErrUnauthenticated)
	}
	now := v.now()
	switch {
	case v.Issuer == "" || c.Iss != v.Issuer:
		return Identity{}, fmt.Errorf("%w: wrong issuer", ErrUnauthenticated)
	case !audience(c.Aud, v.Audience):
		return Identity{}, fmt.Errorf("%w: wrong audience", ErrUnauthenticated)
	case c.Exp == 0 || now.After(time.Unix(c.Exp, 0).Add(leeway)):
		return Identity{}, fmt.Errorf("%w: token expired", ErrUnauthenticated)
	case c.Nbf != 0 && now.Add(leeway).Before(time.Unix(c.Nbf, 0)):
		return Identity{}, fmt.Errorf("%w: token not yet valid", ErrUnauthenticated)
	case c.Username == "":
		return Identity{}, fmt.Errorf("%w: no username claim", ErrUnauthenticated)
	}
	return Identity{User: c.Username, Groups: c.Groups}, nil
}

func audience(raw json.RawMessage, want string) bool {
	if want == "" {
		return false
	}
	var one string
	if json.Unmarshal(raw, &one) == nil {
		return one == want
	}
	var many []string
	if json.Unmarshal(raw, &many) == nil {
		for _, a := range many {
			if a == want {
				return true
			}
		}
	}
	return false
}

func (v *JWT) key(ctx context.Context, kid string) (crypto.PublicKey, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if k, ok := v.keys[kid]; ok {
		return k, nil
	}
	if !v.fetched.IsZero() && v.now().Sub(v.fetched) < time.Minute {
		return nil, fmt.Errorf("%w: unknown signing key", ErrUnauthenticated)
	}
	keys, err := fetchJWKS(ctx, v.HTTP, v.JWKSURL)
	v.fetched = v.now()
	if err != nil {
		return nil, fmt.Errorf("%w: JWKS unavailable: %v", ErrUnauthenticated, err)
	}
	v.keys = keys
	if k, ok := keys[kid]; ok {
		return k, nil
	}
	return nil, fmt.Errorf("%w: unknown signing key", ErrUnauthenticated)
}

func fetchJWKS(ctx context.Context, hc *http.Client, url string) (map[string]crypto.PublicKey, error) {
	if url == "" {
		return nil, errors.New("no JWKS URL")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	if hc == nil {
		hc = &http.Client{Timeout: 10 * time.Second}
	}
	resp, err := hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("JWKS: %d", resp.StatusCode)
	}
	var set struct {
		Keys []struct {
			Kty, Kid, Crv, N, E, X, Y string
		} `json:"keys"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&set); err != nil {
		return nil, err
	}
	out := map[string]crypto.PublicKey{}
	for _, k := range set.Keys {
		switch k.Kty {
		case "RSA":
			n, err1 := b64(k.N)
			e, err2 := b64(k.E)
			if err1 != nil || err2 != nil || len(n) < 256 {
				continue // malformed or under 2048 bits
			}
			out[k.Kid] = &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(new(big.Int).SetBytes(e).Int64())}
		case "EC":
			if k.Crv != "P-256" {
				continue
			}
			x, err1 := b64(k.X)
			y, err2 := b64(k.Y)
			if err1 != nil || err2 != nil {
				continue
			}
			pk := &ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(x), Y: new(big.Int).SetBytes(y)}
			if !pk.Curve.IsOnCurve(pk.X, pk.Y) {
				continue
			}
			out[k.Kid] = pk
		}
	}
	return out, nil
}

// ------------------------------------------------------- proxy-secret mode

// ProxySecret trusts Authentik's headers only when Traefik's shared secret
// header matches the mounted Secret.
type ProxySecret struct {
	SecretFile string
	Group      string
}

// Authenticate checks the secret, then the username and group headers.
func (p ProxySecret) Authenticate(r *http.Request) (Identity, error) {
	want, err := os.ReadFile(p.SecretFile)
	secret := strings.TrimSpace(string(want))
	if err != nil || len(secret) < 32 {
		return Identity{}, ErrNotConfigured
	}
	got := r.Header.Get(HeaderSecret)
	if subtle.ConstantTimeCompare([]byte(got), []byte(secret)) != 1 {
		return Identity{}, fmt.Errorf("%w: proxy secret missing or wrong", ErrUnauthenticated)
	}
	user := r.Header.Get(HeaderUser)
	if user == "" {
		return Identity{}, fmt.Errorf("%w: no username", ErrUnauthenticated)
	}
	id := Identity{User: user}
	for _, g := range strings.Split(r.Header.Get(HeaderGroups), "|") {
		if g = strings.TrimSpace(g); g != "" {
			id.Groups = append(id.Groups, g)
		}
	}
	if p.Group == "" || !id.In(p.Group) {
		return Identity{}, ErrForbidden
	}
	return id, nil
}
