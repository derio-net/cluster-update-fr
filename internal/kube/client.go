// Package kube is a deliberately small Kubernetes REST client.
//
// The console reads the clusters freely (Get) but writes almost nothing
// (R14): the ONLY writes it can express are creating and deleting pods and
// Secrets in the upgrade-sessions namespace, plus the per-upgrade RoleBinding
// (named upgrade-session-*) instantiated from frank's template. That rule is
// enforced here, before a request is built, so no other package can widen
// it — and a client without a WritePolicy (every Hop client) cannot write at
// all.
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
	"net/http"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/derio-net/cluster-update-fr/internal/scrub"
)

// ErrForbiddenWrite is returned, without any request, for a write outside
// the write policy.
var ErrForbiddenWrite = errors.New("kube: write outside the console's write policy refused")

// SessionPrefix names every object the console may create outside the
// session namespace (the per-upgrade RoleBinding).
const SessionPrefix = "upgrade-session-"

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

// WritePolicy is the console's entire write surface.
type WritePolicy struct {
	SessionNamespace string
}

func (p *WritePolicy) allows(ns, resource, name string) bool {
	if p == nil || p.SessionNamespace == "" {
		return false
	}
	switch resource {
	case "pods", "secrets":
		return ns == p.SessionNamespace
	case "rolebindings":
		return strings.HasPrefix(name, SessionPrefix)
	}
	return false
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
	for _, cl := range kc.Clusters {
		if cl.Name != clusterName {
			continue
		}
		c.Server = strings.TrimRight(cl.Cluster.Server, "/")
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
	c.Token = func() string { return bearer }
	c.HTTP = &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{TLSClientConfig: tlsCfg}}
	return c, nil
}

// Get decodes the JSON at an API path (e.g. /api/v1/pods) into out.
func (c *Client) Get(ctx context.Context, path string, out any) error {
	return c.do(ctx, http.MethodGet, path, nil, out)
}

// Create POSTs obj into resource in namespace ns, if the write policy allows.
func (c *Client) Create(ctx context.Context, ns, resource string, obj any) error {
	if !c.Writes.allows(ns, resource, objectName(obj)) {
		return ErrForbiddenWrite
	}
	body, err := json.Marshal(obj)
	if err != nil {
		return err
	}
	return c.do(ctx, http.MethodPost, collection(ns, resource), body, nil)
}

// Delete removes ns/resource/name, if the write policy allows.
func (c *Client) Delete(ctx context.Context, ns, resource, name string) error {
	if !c.Writes.allows(ns, resource, name) {
		return ErrForbiddenWrite
	}
	return c.do(ctx, http.MethodDelete, collection(ns, resource)+"/"+name, []byte(`{"propagationPolicy":"Background"}`), nil)
}

// ObjectPath is the GET path of one namespaced object.
func ObjectPath(ns, resource, name string) string { return collection(ns, resource) + "/" + name }

func collection(ns, resource string) string {
	if resource == "rolebindings" {
		return "/apis/rbac.authorization.k8s.io/v1/namespaces/" + ns + "/rolebindings"
	}
	return "/api/v1/namespaces/" + ns + "/" + resource
}

func objectName(obj any) string {
	b, err := json.Marshal(obj)
	if err != nil {
		return ""
	}
	var m struct {
		Metadata struct {
			Name string `json:"name"`
		} `json:"metadata"`
	}
	_ = json.Unmarshal(b, &m)
	return m.Metadata.Name
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
		return fmt.Errorf("kube: %s %s: %s", method, path, scrub.String(err.Error()))
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
