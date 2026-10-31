package frankrepo

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/derio-net/cluster-update-fr/internal/scrub"
)

// ErrNotFound means the path is absent from the repo (not declared).
var ErrNotFound = errors.New("frankrepo: not found")

// Source reads files of the frank repository.
type Source interface {
	Read(ctx context.Context, path string) ([]byte, error)
	// List returns the *.yaml file names directly under dir.
	List(ctx context.Context, dir string) ([]string, error)
}

// FSSource reads a local checkout (tests, local runs).
type FSSource struct{ Root string }

func (s FSSource) Read(_ context.Context, path string) ([]byte, error) {
	b, err := os.ReadFile(filepath.Join(s.Root, filepath.FromSlash(path)))
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrNotFound
	}
	return b, err
}

func (s FSSource) List(_ context.Context, dir string) ([]string, error) {
	entries, err := os.ReadDir(filepath.Join(s.Root, filepath.FromSlash(dir)))
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	var names []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".yaml") {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	return names, nil
}

// GitHubSource reads through the GitHub contents API.
type GitHubSource struct {
	API   string // https://api.github.com
	Repo  string // owner/name
	Ref   string
	Token func() string
	HTTP  *http.Client
}

func (s GitHubSource) get(ctx context.Context, path string, out any) error {
	u := fmt.Sprintf("%s/repos/%s/contents/%s?ref=%s", s.API, s.Repo, path, url.QueryEscape(s.Ref))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	if s.Token != nil {
		if t := s.Token(); t != "" {
			req.Header.Set("Authorization", "Bearer "+t)
		}
	}
	client := s.HTTP
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return ErrNotFound
	}
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("frankrepo: GET %s: %d %s", path, resp.StatusCode, scrub.String(string(b)))
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

func (s GitHubSource) Read(ctx context.Context, path string) ([]byte, error) {
	var f struct {
		Content  string `json:"content"`
		Encoding string `json:"encoding"`
	}
	if err := s.get(ctx, path, &f); err != nil {
		return nil, err
	}
	if f.Encoding != "base64" {
		return nil, fmt.Errorf("frankrepo: %s: unexpected encoding %q", path, f.Encoding)
	}
	return base64.StdEncoding.DecodeString(strings.ReplaceAll(f.Content, "\n", ""))
}

func (s GitHubSource) List(ctx context.Context, dir string) ([]string, error) {
	var entries []struct {
		Name string `json:"name"`
		Type string `json:"type"`
	}
	if err := s.get(ctx, dir, &entries); err != nil {
		return nil, err
	}
	var names []string
	for _, e := range entries {
		if e.Type == "file" && strings.HasSuffix(e.Name, ".yaml") {
			names = append(names, e.Name)
		}
	}
	sort.Strings(names)
	return names, nil
}
