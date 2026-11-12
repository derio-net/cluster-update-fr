package kube

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/pem"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
)

// fakeSOCKS5 is a minimal no-auth SOCKS5 CONNECT proxy that counts the
// connections it relays.
func fakeSOCKS5(t *testing.T) (addr string, relayed *int32) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	var n int32
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				hdr := make([]byte, 2)
				if _, err := io.ReadFull(c, hdr); err != nil || hdr[0] != 5 {
					return
				}
				if _, err := io.ReadFull(c, make([]byte, hdr[1])); err != nil {
					return
				}
				c.Write([]byte{5, 0})
				req := make([]byte, 4)
				if _, err := io.ReadFull(c, req); err != nil || req[1] != 1 {
					return
				}
				var host string
				switch req[3] {
				case 1:
					ip := make([]byte, 4)
					io.ReadFull(c, ip)
					host = net.IP(ip).String()
				case 3:
					l := make([]byte, 1)
					io.ReadFull(c, l)
					h := make([]byte, l[0])
					io.ReadFull(c, h)
					host = string(h)
				default:
					return
				}
				pb := make([]byte, 2)
				io.ReadFull(c, pb)
				target, err := net.Dial("tcp", net.JoinHostPort(host, strconv.Itoa(int(binary.BigEndian.Uint16(pb)))))
				if err != nil {
					c.Write([]byte{5, 5, 0, 1, 0, 0, 0, 0, 0, 0})
					return
				}
				defer target.Close()
				atomic.AddInt32(&n, 1)
				c.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0})
				go io.Copy(target, c)
				io.Copy(c, target)
			}(conn)
		}
	}()
	return ln.Addr().String(), &n
}

// countingTLS is a TLS API server that counts every TCP connection it sees.
func countingTLS(t *testing.T) (*httptest.Server, *int32) {
	t.Helper()
	var conns int32
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"ok":true}`))
	}))
	srv.Config.ConnState = func(_ net.Conn, s http.ConnState) {
		if s == http.StateNew {
			atomic.AddInt32(&conns, 1)
		}
	}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv, &conns
}

func writeKubeconfig(t *testing.T, server, caPEM, proxyURL string) string {
	t.Helper()
	cluster := `server: "` + server + `"`
	if caPEM != "" {
		cluster += "\n    certificate-authority-data: " + base64.StdEncoding.EncodeToString([]byte(caPEM))
	}
	if proxyURL != "" {
		cluster += `
    proxy-url: "` + proxyURL + `"`
	}
	content := `apiVersion: v1
kind: Config
current-context: hop
contexts:
- name: hop
  context: {cluster: hop, user: reader}
clusters:
- name: hop
  cluster:
    ` + cluster + `
users:
- name: reader
  user: {token: tkn}
`
	p := filepath.Join(t.TempDir(), "kubeconfig")
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func caOf(srv *httptest.Server) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}))
}

func TestKubeconfigSOCKS5ProxyIsUsedAndTLSStillVerified(t *testing.T) {
	srv, _ := countingTLS(t)
	paddr, relayed := fakeSOCKS5(t)

	c, err := FromKubeconfig(writeKubeconfig(t, srv.URL, caOf(srv), "socks5://"+paddr))
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]bool
	if err := c.Get(context.Background(), "/api/v1/x", &out); err != nil {
		t.Fatalf("get through proxy: %v", err)
	}
	if !out["ok"] || atomic.LoadInt32(relayed) != 1 {
		t.Fatalf("out=%v relayed=%d: the request must go through the SOCKS5 proxy", out, *relayed)
	}

	// Same proxy, no CA for the server's self-signed cert: the proxy carries
	// the bytes but TLS verification still rejects the server.
	c2, err := FromKubeconfig(writeKubeconfig(t, srv.URL, "", "socks5://"+paddr))
	if err != nil {
		t.Fatal(err)
	}
	err = c2.Get(context.Background(), "/api/v1/x", &out)
	if err == nil || !strings.Contains(err.Error(), "certificate") {
		t.Fatalf("unverified server must fail TLS through the proxy, got %v", err)
	}
	if atomic.LoadInt32(relayed) != 2 {
		t.Errorf("relayed = %d, want 2 (second request also proxied)", *relayed)
	}
}

func TestKubeconfigHTTPProxySetsTransportProxy(t *testing.T) {
	c, err := FromKubeconfig(writeKubeconfig(t, "https://hop-1:6443", "", "http://127.0.0.1:3128"))
	if err != nil {
		t.Fatal(err)
	}
	tr := c.HTTP.Transport.(*http.Transport)
	req, _ := http.NewRequest(http.MethodGet, "https://hop-1:6443/api", nil)
	u, err := tr.Proxy(req)
	if err != nil || u == nil || u.Host != "127.0.0.1:3128" {
		t.Fatalf("proxy = %v, %v", u, err)
	}
	if tr.TLSClientConfig.InsecureSkipVerify {
		t.Error("TLS verification must be unchanged by a proxy")
	}
}

func TestKubeconfigWithoutProxyIgnoresEnvironmentProxy(t *testing.T) {
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:1")
	c, err := FromKubeconfig(writeKubeconfig(t, "https://hop-1:6443", "", ""))
	if err != nil {
		t.Fatal(err)
	}
	if c.HTTP.Transport.(*http.Transport).Proxy != nil {
		t.Error("no proxy-url means no proxy, never the environment's")
	}
}

func TestKubeconfigInvalidProxyURLFailsClosed(t *testing.T) {
	srv, conns := countingTLS(t)
	for _, bad := range []string{"socks5://", "ftp://127.0.0.1:21", "://nope", "socks5:///path", "localhost:1055"} {
		if _, err := FromKubeconfig(writeKubeconfig(t, srv.URL, caOf(srv), bad)); err == nil {
			t.Errorf("proxy-url %q must be refused", bad)
		}
	}
	if atomic.LoadInt32(conns) != 0 {
		t.Errorf("a refused kubeconfig must never connect directly (%d connections)", *conns)
	}
}

func TestKubeconfigUnreachableProxyNeverFallsBackToDirect(t *testing.T) {
	srv, conns := countingTLS(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	dead := ln.Addr().String()
	ln.Close()

	c, err := FromKubeconfig(writeKubeconfig(t, srv.URL, caOf(srv), "socks5://"+dead))
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Get(context.Background(), "/api/v1/x", &struct{}{}); err == nil {
		t.Fatal("an unreachable proxy must fail the request")
	}
	if atomic.LoadInt32(conns) != 0 {
		t.Errorf("no direct connection may be attempted (%d connections)", *conns)
	}
}
