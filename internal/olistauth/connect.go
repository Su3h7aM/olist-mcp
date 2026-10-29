package olistauth

import (
	"context"
	"errors"
	"net/url"

	"github.com/openbot/olist-mcp/internal/tokenstore"
	"golang.org/x/oauth2"
)

// AuthorizationURL builds the provider URL. The caller must generate a
// cryptographically random, single-use state and bind it to the authenticated
// owner and selected account before redirecting a browser.
func AuthorizationURL(config oauth2.Config, state string) (string, error) {
	if state == "" || config.ClientID == "" || config.RedirectURL == "" {
		return "", errors.New("OAuth client, redirect URI and state required")
	}
	u, err := url.Parse(config.Endpoint.AuthURL)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return "", errors.New("invalid authorization endpoint")
	}
	return config.AuthCodeURL(state), nil
}

// Exchange stores the received credentials before signaling success. The
// caller must validate and consume the bound state before calling this method.
func Exchange(ctx context.Context, config oauth2.Config, store TokenStore, account, code string) error {
	if account == "" || code == "" || store == nil {
		return errors.New("account, authorization code and token store required")
	}
	tok, err := config.Exchange(ctx, code)
	if err != nil {
		return errors.New("Olist authorization code exchange failed")
	}
	if tok.AccessToken == "" || tok.RefreshToken == "" || tok.Expiry.IsZero() {
		return errors.New("Olist returned incomplete credentials")
	}
	if err = store.Put(ctx, account, tokenstore.Token{AccessToken: tok.AccessToken, RefreshToken: tok.RefreshToken, Expiry: tok.Expiry}); err != nil {
		return errors.New("failed to persist Olist credentials")
	}
	return nil
}
