// Package kube is a deliberately small Kubernetes REST client.
//
// The console reads the clusters freely (Get) but writes almost nothing
// (R14). Its ENTIRE write surface is an allowlist of (verb, resource,
// namespace) tuples:
//
//	create | delete   pods          <session namespace>
//	create | delete   secrets       <session namespace>
//
// Nothing cluster-scoped, nothing in any other namespace, and no RBAC object
// at all (a RoleBinding is a privilege grant; frank pre-binds every role a
// session needs). Every object name must start with SessionPrefix; a create
// must carry the label ManagedByLabel=ManagedBy; a delete first reads the
// object and refuses unless it carries that label, so the console can never
// delete something it did not make (c1s-r4). The check runs
// before a request is built: the namespace must equal the configured session
// namespace, and both namespace and name must be DNS-1123 labels, so a name
// carrying '/', '..', '?', '#', '%' or uppercase can never reach a different
// API path (no validator/request differential). Path segments are also
// escaped when the request is built, as defence in depth. A client without a
// WritePolicy (every Hop client) cannot write at all.
//
// frank's RBAC for the console's ServiceAccount is the SECOND layer, not the
// guard: this package must refuse a write even if RBAC would allow it.
package kube

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"golang.org/x/net/proxy"
	"gopkg.in/yaml.v3"

	"github.com/derio-net/cluster-update-fr/internal/scrub"
)

// ErrForbiddenWrite is returned, without any request, for a write outside
// the write policy.
var ErrForbiddenWrite = errors.New("kube: write outside the console's write policy refused")

// SessionPrefix starts the name of every object the console creates (the
// session pod "us-<id>-<hash>" and its "-creds"/"-brief" Secrets).
const SessionPrefix = "us-"

// The label every console-created object carries, and the only objects a
// delete may touch.
const (
	ManagedByLabel = "app.kubernetes.io/managed-by"
	ManagedBy      = "cluster-update-fr"
)

// APIError is a non-2xx answer from the API server.
type APIError struct {
	Code    int
	Reason  string
	Message string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("kube: %d %s: %s", e.Code, e.Reason, e.Message)
}

// IsNotFound reports a 404.
func IsNotFound(err error) bool {
	var e *APIError
	return errors.As(err, &e) && e.Code == http.StatusNotFound
}

// IsConflict reports a 409 (AlreadyExists).
func IsConflict(err error) bool {
	var e *APIError
	return errors.As(err, &e) && e.Code == http.StatusConflict
}

// TransportError is a request that never got an HTTP answer (connection
// refused/reset, DNS, TLS, timeout). Its message is scrubbed.
type TransportError struct{ Msg string }

func (e *TransportError) Error() string { return e.Msg }

// IsTransient reports an error that says nothing about the object: no
// answer at all, a timeout, 5xx or 429. 403, 404 and a malformed answer are
// NOT transient — they are evidence (c1d-r2).
func IsTransient(err error) bool {
	var t *TransportError
	var e *APIError
	switch {
	case err == nil:
		return false
	case errors.As(err, &t), errors.Is(err, context.DeadlineExceeded), errors.Is(err, context.Canceled):
		return true
	case errors.As(err, &e):
		return e.Code >= 500 || e.Code == http.StatusTooManyRequests
	}
	return false
}

// WritePolicy is the console's entire write surface (see the package doc).
type WritePolicy struct {
	SessionNamespace string
}

// Verb is a write verb.
type Verb string

// The two write verbs.
const (
	VerbCreate Verb = "create"
	VerbDelete Verb = "delete"
)

// writable is the resource half of the allowlist; every entry is namespaced
// and only ever written in the session namespace.
var writable = map[string]bool{"pods": true, "secrets": true}

var dns1123Label = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`)

// ValidName reports whether s is a DNS-1123 label of at most max characters.
func ValidName(s string, max int) bool {
	return len(s) > 0 && len(s) <= max && dns1123Label.MatchString(s)
}

func (p *WritePolicy) allows(v Verb, ns, resource, name string) bool {
	if p == nil || p.SessionNamespace == "" {
		return false
	}
	if v != VerbCreate && v != VerbDelete {
		return false
	}
	if ns != p.SessionNamespace || !ValidName(ns, 63) {
		return false
	}
	if !writable[resource] {
		return false
	}
	return ValidName(name, 253) && strings.HasPrefix(name, SessionPrefix)
}

// Client talks to one API server.
type Client struct {
	Server string
	Token  func() string
	HTTP   *http.Client
	Writes *WritePolicy // nil = read-only
}

const saDir = "/var/run/secrets/kubernetes.io/serviceaccount"

// InCluster builds a client from the pod's ServiceAccount. The token file is
// re-read on every request (projected tokens rotate).
func InCluster() (*Client, error) {
	host, port := os.Getenv("KUBERNETES_SERVICE_HOST"), os.Getenv("KUBERNETES_SERVICE_PORT")
	if host == "" || port == "" {
		return nil, errors.New("kube: not running in a cluster")
	}
	ca, err := os.ReadFile(saDir + "/ca.crt")
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(ca)
	return &Client{
		Server: "https://" + host + ":" + port,
		Token: func() string {
			b, _ := os.ReadFile(saDir + "/token")
			return strings.TrimSpace(string(b))
		},
		HTTP: &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}}},
	}, nil
}

type kubeconfig struct {
	CurrentContext string `yaml:"current-context"`
	Contexts       []struct {
		Name    string `yaml:"name"`
		Context struct {
			Cluster string `yaml:"cluster"`
			User    string `yaml:"user"`
		} `yaml:"context"`
	} `yaml:"contexts"`
	Clusters []struct {
		Name    string `yaml:"name"`
		Cluster struct {
			Server   string `yaml:"server"`
			CAData   string `yaml:"certificate-authority-data"`
			Insecure bool   `yaml:"insecure-skip-tls-verify"`
			ProxyURL string `yaml:"proxy-url"`
		} `yaml:"cluster"`
	} `yaml:"clusters"`
	Users []struct {
		Name string `yaml:"name"`
		User struct {
			Token    string `yaml:"token"`
			CertData string `yaml:"client-certificate-data"`
			KeyData  string `yaml:"client-key-data"`
		} `yaml:"user"`
	} `yaml:"users"`
}

// FromKubeconfig builds a READ-ONLY client from a kubeconfig file (the Hop
// read-only kubeconfig reached over the tailnet).
func FromKubeconfig(path string) (*Client, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("kube: kubeconfig: %w", err)
	}
	var kc kubeconfig
	if err := yaml.Unmarshal(b, &kc); err != nil {
		return nil, fmt.Errorf("kube: kubeconfig: %w", err)
	}
	clusterName, userName := "", ""
	for _, c := range kc.Contexts {
		if c.Name == kc.CurrentContext || (kc.CurrentContext == "" && clusterName == "") {
			clusterName, userName = c.Context.Cluster, c.Context.User
		}
	}
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
	c := &Client{}
	proxyURL := ""
	for _, cl := range kc.Clusters {
		if cl.Name != clusterName {
			continue
		}
		c.Server = strings.TrimRight(cl.Cluster.Server, "/")
		proxyURL = cl.Cluster.ProxyURL
		if cl.Cluster.CAData != "" {
			ca, err := base64.StdEncoding.DecodeString(cl.Cluster.CAData)
			if err != nil {
				return nil, fmt.Errorf("kube: kubeconfig CA: %w", err)
			}
			pool := x509.NewCertPool()
			pool.AppendCertsFromPEM(ca)
			tlsCfg.RootCAs = pool
		}
		tlsCfg.InsecureSkipVerify = cl.Cluster.Insecure // #nosec G402 -- honours the kubeconfig's own choice
	}
	if c.Server == "" {
		return nil, fmt.Errorf("kube: kubeconfig has no cluster %q", clusterName)
	}
	bearer := ""
	for _, u := range kc.Users {
		if u.Name != userName {
			continue
		}
		bearer = u.User.Token
		if u.User.CertData != "" && u.User.KeyData != "" {
			cert, err1 := base64.StdEncoding.DecodeString(u.User.CertData)
			key, err2 := base64.StdEncoding.DecodeString(u.User.KeyData)
			if err1 != nil || err2 != nil {
				return nil, errors.New("kube: kubeconfig client certificate is not base64")
			}
			pair, err := tls.X509KeyPair(cert, key)
			if err != nil {
				return nil, errors.New("kube: kubeconfig client certificate is invalid")
			}
			tlsCfg.Certificates = []tls.Certificate{pair}
		}
	}
	tr := &http.Transport{TLSClientConfig: tlsCfg} // Proxy nil: never the environment's proxy
	if err := applyProxy(tr, proxyURL); err != nil {
		return nil, err
	}
	c.Token = func() string { return bearer }
	c.HTTP = &http.Client{Timeout: 30 * time.Second, Transport: tr}
	return c, nil
}

// applyProxy routes tr through the kubeconfig cluster's proxy-url (Hop's
// kubeconfig names the userspace tailscale sidecar, socks5://localhost:1055).
// socks5/socks5h dial through a SOCKS5 dialer; http/https set tr.Proxy. TLS to
// the API server is unchanged either way: the proxy carries the bytes, the
// transport still verifies the server against the kubeconfig's CA. A
// proxy-url that is set but unparseable or of an unknown scheme is an error,
// never a silent direct connection; an unreachable proxy fails the request
// (there is no fallback dial). An absent proxy-url means a direct connection,
// as kubectl does.
func applyProxy(tr *http.Transport, raw string) error {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.Hostname() == "" {
		return errors.New("kube: kubeconfig proxy-url is invalid")
	}
	switch u.Scheme {
	case "socks5", "socks5h":
		var auth *proxy.Auth
		if u.User != nil {
			pw, _ := u.User.Password()
			auth = &proxy.Auth{User: u.User.Username(), Password: pw}
		}
		d, err := proxy.SOCKS5("tcp", u.Host, auth, &net.Dialer{Timeout: 10 * time.Second})
		if err != nil {
			return fmt.Errorf("kube: kubeconfig proxy-url: %w", err)
		}
		cd, ok := d.(proxy.ContextDialer)
		if !ok {
			return errors.New("kube: kubeconfig proxy-url: SOCKS5 dialer has no context support")
		}
		tr.DialContext = cd.DialContext
	case "http", "https":
		tr.Proxy = http.ProxyURL(u)
	default:
		return fmt.Errorf("kube: kubeconfig proxy-url scheme %q is not supported", u.Scheme)
	}
	return nil
}

// Get decodes the JSON at an API path (e.g. /api/v1/pods) into out.
func (c *Client) Get(ctx context.Context, path string, out any) error {
	return c.do(ctx, http.MethodGet, path, nil, out)
}

// Create POSTs obj into resource in namespace ns, if the write policy allows.
// The object's metadata.namespace, when set, must equal ns.
func (c *Client) Create(ctx context.Context, ns, resource string, obj any) error {
	m := objectMeta(obj)
	if (m.Namespace != "" && m.Namespace != ns) || m.Labels[ManagedByLabel] != ManagedBy || !c.Writes.allows(VerbCreate, ns, resource, m.Name) {
		return ErrForbiddenWrite
	}
	body, err := json.Marshal(obj)
	if err != nil {
		return err
	}
	return c.do(ctx, http.MethodPost, collection(ns, resource), body, nil)
}

// Delete removes ns/resource/name, if the write policy allows AND the live
// object carries the console's managed-by label. The delete is pinned to
// the uid that was checked (a precondition), so a swap between the read and
// the delete fails instead of deleting the new object.
func (c *Client) Delete(ctx context.Context, ns, resource, name string) error {
	if !c.Writes.allows(VerbDelete, ns, resource, name) {
		return ErrForbiddenWrite
	}
	var live struct {
		Metadata Meta `json:"metadata"`
	}
	if err := c.Get(ctx, ObjectPath(ns, resource, name), &live); err != nil {
		return err
	}
	if live.Metadata.Labels[ManagedByLabel] != ManagedBy {
		return ErrForbiddenWrite
	}
	opts, _ := json.Marshal(map[string]any{"propagationPolicy": "Background", "preconditions": map[string]string{"uid": live.Metadata.UID}})
	return c.do(ctx, http.MethodDelete, ObjectPath(ns, resource, name), opts, nil)
}

// DeleteUID removes ns/resource/name only if it is still the exact object
// with uid — the console recorded that uid when it created the object, so
// it is the console's whatever its labels say now (a stripped managed-by
// label cannot shield it). The delete carries a uid precondition, so a
// swapped object is never touched. Name/namespace/resource policy applies.
func (c *Client) DeleteUID(ctx context.Context, ns, resource, name, uid string) error {
	if uid == "" || !c.Writes.allows(VerbDelete, ns, resource, name) {
		return ErrForbiddenWrite
	}
	opts, _ := json.Marshal(map[string]any{"propagationPolicy": "Background", "preconditions": map[string]string{"uid": uid}})
	return c.do(ctx, http.MethodDelete, ObjectPath(ns, resource, name), opts, nil)
}

// ObjectPath is the GET path of one namespaced object (segments escaped).
func ObjectPath(ns, resource, name string) string {
	return collection(ns, resource) + "/" + url.PathEscape(name)
}

func collection(ns, resource string) string {
	return "/api/v1/namespaces/" + url.PathEscape(ns) + "/" + url.PathEscape(resource)
}

// Meta is the object metadata the write guard reads.
type Meta struct {
	Name        string            `json:"name"`
	Namespace   string            `json:"namespace"`
	UID         string            `json:"uid"`
	Labels      map[string]string `json:"labels"`
	Annotations map[string]string `json:"annotations"`
}

func objectMeta(obj any) Meta {
	b, err := json.Marshal(obj)
	if err != nil {
		return Meta{}
	}
	var m struct {
		Metadata Meta `json:"metadata"`
	}
	_ = json.Unmarshal(b, &m)
	return m.Metadata
}

func (c *Client) do(ctx context.Context, method, path string, body []byte, out any) error {
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.Server+path, rd)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.Token != nil {
		if t := c.Token(); t != "" {
			req.Header.Set("Authorization", "Bearer "+t)
		}
	}
	client := c.HTTP
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Do(req)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return fmt.Errorf("kube: %s %s: %w", method, path, ctxErr)
		}
		return &TransportError{Msg: fmt.Sprintf("kube: %s %s: %s", method, path, scrub.String(err.Error()))}
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		var st struct {
			Reason  string `json:"reason"`
			Message string `json:"message"`
		}
		_ = json.Unmarshal(b, &st)
		if st.Message == "" {
			st.Message = strings.TrimSpace(string(b))
		}
		return &APIError{Code: resp.StatusCode, Reason: st.Reason, Message: scrub.String(st.Message)}
	}
	if out == nil {
		_, _ = io.Copy(io.Discard, resp.Body)
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(out)
}
