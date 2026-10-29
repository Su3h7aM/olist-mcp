// Package olistauth maintains one account's OAuth token.
package olistauth

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/openbot/olist-mcp/internal/tokenstore"
	"golang.org/x/oauth2"
)

type TokenStore interface {
	Get(context.Context, string) (tokenstore.Token, error)
	Put(context.Context, string, tokenstore.Token) error
}
type Manager struct {
	account     string
	config      oauth2.Config
	store       TokenStore
	mu          sync.Mutex
	needsReauth bool
}

func New(account string, config oauth2.Config, store TokenStore) (*Manager, error) {
	if account == "" || config.ClientID == "" || config.ClientSecret == "" || config.Endpoint.TokenURL == "" || store == nil {
		return nil, errors.New("account, OAuth configuration and token store required")
	}
	return &Manager{account: account, config: config, store: store}, nil
}

// AccessToken serializes refresh for the account and persists the new token
// before returning it. A failed persistence requires reauthorization if the
// provider rotated the refresh token.
func (m *Manager) AccessToken(ctx context.Context) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.needsReauth {
		return "", errors.New("account requires reauthorization")
	}
	saved, err := m.store.Get(ctx, m.account)
	if err != nil {
		return "", err
	}
	if saved.AccessToken != "" && saved.Expiry.After(time.Now().Add(time.Minute)) {
		return saved.AccessToken, nil
	}
	if saved.RefreshToken == "" {
		return "", errors.New("account requires reauthorization")
	}
	source := m.config.TokenSource(ctx, &oauth2.Token{RefreshToken: saved.RefreshToken, Expiry: time.Unix(1, 0)})
	refreshed, err := source.Token()
	if err != nil {
		var retrieve *oauth2.RetrieveError
		if errors.As(err, &retrieve) && retrieve.ErrorCode == "invalid_grant" {
			m.needsReauth = true
			return "", errors.New("account requires reauthorization")
		}
		if ctx.Err() != nil {
			return "", ctx.Err()
		}
		return "", errors.New("Olist token refresh failed")
	}
	if refreshed.AccessToken == "" || refreshed.RefreshToken == "" {
		return "", errors.New("provider returned incomplete token")
	}
	if err = m.store.Put(ctx, m.account, tokenstore.Token{AccessToken: refreshed.AccessToken, RefreshToken: refreshed.RefreshToken, Expiry: refreshed.Expiry}); err != nil {
		m.needsReauth = true
		return "", errors.New("failed to persist refreshed token; account requires reauthorization")
	}
	return refreshed.AccessToken, nil
}
