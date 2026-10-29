// Package olist provides a bounded, read-only client for the Olist ERP API.
package olist

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const BaseURL = "https://api.tiny.com.br/public-api/v3"
const maxResponse = 8 << 20

type Client struct {
	base  *url.URL
	http  *http.Client
	token func(context.Context) (string, error)
}
type HTTPError struct {
	StatusCode int
	RetryAfter string
}

func (e *HTTPError) Error() string { return fmt.Sprintf("olist API returned HTTP %d", e.StatusCode) }

// NewClient takes an account-specific token provider. Tokens are never stored in URLs or errors.
func NewClient(base string, token func(context.Context) (string, error)) (*Client, error) {
	u, err := url.Parse(base)
	if err != nil || u == nil || u.Host == "" || (u.Scheme != "https" && !(u.Scheme == "http" && (u.Hostname() == "127.0.0.1" || u.Hostname() == "localhost" || u.Hostname() == "::1"))) || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, errors.New("invalid API base URL")
	}
	if token == nil {
		return nil, errors.New("token provider required")
	}
	return &Client{base: u, token: token, http: &http.Client{Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}, nil
}

// Get retrieves a JSON API response; path must be an absolute API path with no query.
func (c *Client) Get(ctx context.Context, path string, query url.Values) (json.RawMessage, error) {
	if !strings.HasPrefix(path, "/") || strings.HasPrefix(path, "//") || strings.ContainsAny(path, "?#\\") {
		return nil, errors.New("invalid API path")
	}
	for _, part := range strings.Split(path, "/") {
		if part == ".." || part == "." {
			return nil, errors.New("invalid API path")
		}
	}
	u := *c.base
	u.Path = strings.TrimRight(c.base.Path, "/") + path
	u.RawPath = ""
	u.RawQuery = query.Encode()
	token, err := c.token(ctx)
	if err != nil {
		return nil, err
	}
	if token == "" {
		return nil, errors.New("empty access token")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("olist request failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, &HTTPError{resp.StatusCode, resp.Header.Get("Retry-After")}
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxResponse+1))
	if err != nil {
		return nil, err
	}
	if len(b) > maxResponse {
		return nil, errors.New("olist response exceeds size limit")
	}
	if !json.Valid(b) {
		return nil, errors.New("olist returned invalid JSON")
	}
	return json.RawMessage(b), nil
}
