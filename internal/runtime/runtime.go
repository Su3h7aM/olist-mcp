// Package runtime composes the per-account Olist pieces: configuration, OAuth
// token management, rate-limited API clients, the mirror store and tracked
// sync jobs, plus the owner-protected connection handlers. It mounts no
// listener and implements no MCP OAuth.
package runtime

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/openbot/olist-mcp/internal/admin"
	"github.com/openbot/olist-mcp/internal/config"
	"github.com/openbot/olist-mcp/internal/oauthstate"
	"github.com/openbot/olist-mcp/internal/olist"
	"github.com/openbot/olist-mcp/internal/olistauth"
	"github.com/openbot/olist-mcp/internal/ratelimit"
	"github.com/openbot/olist-mcp/internal/scheduler"
	"github.com/openbot/olist-mcp/internal/store"
	"github.com/openbot/olist-mcp/internal/syncer"
	"github.com/openbot/olist-mcp/internal/tokenstore"
	"golang.org/x/oauth2"
)

const (
	// CallbackPath is the one redirect URI shared by every account (decision 3).
	CallbackPath = "/oauth/olist/callback"
	// defaultAuthURL and defaultTokenURL are the Keycloak endpoints recorded in
	// ARCHITECTURE.md. They are not verified against a live provider here.
	defaultAuthURL  = "https://accounts.tiny.com.br/realms/tiny/protocol/openid-connect/auth"
	defaultTokenURL = "https://accounts.tiny.com.br/realms/tiny/protocol/openid-connect/token"
	// reservedPercent keeps about 20% of each account's reads for on-demand calls.
	reservedPercent = 20
	stateTTL        = 10 * time.Minute
	stateCapacity   = 1000
)

// Options are the injected dependencies. Only Config, OwnerAuth, TokenKey and
// DataDir-derived paths are required; the rest have defaults. Tests inject the
// provider endpoints and the secret reader.
type Options struct {
	Config *config.Config
	// OwnerAuth authenticates the owner for the admin handlers. Required.
	OwnerAuth admin.Owner
	// TokenKey encrypts stored Olist tokens. It must be 32 bytes and come from
	// outside the database.
	TokenKey []byte
	// OAuthAuthURL and OAuthTokenURL override the Keycloak endpoints. The auth
	// URL must be https. The token URL must be https or loopback http.
	OAuthAuthURL  string
	OAuthTokenURL string
	// APIBaseURL overrides the Olist API base. Default olist.BaseURL.
	APIBaseURL string
	// ReadSecret loads a client secret file. Default os.ReadFile.
	ReadSecret func(path string) ([]byte, error)
}

type account struct {
	syncSlot chan struct{}
	id       string
	oauth    oauth2.Config
	tokens   *olistauth.Manager
	reader   *olist.LimitedReader
}

// Runtime holds the composed services. Close releases both databases.
type Runtime struct {
	mirror   *store.Store
	tokens   *tokenstore.Store
	states   *oauthstate.Registry
	admin    *admin.Handler
	accounts map[string]*account
	order    []string
}

// New opens the mirror and token databases under the configured data directory
// and builds each configured account. It reads each client secret file once.
// It does not contact Olist or the provider.
func New(ctx context.Context, opts Options) (*Runtime, error) {
	if opts.Config == nil {
		return nil, errors.New("configuration required")
	}
	if err := opts.Config.Validate(); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}
	if opts.OwnerAuth == nil {
		return nil, errors.New("owner authentication required")
	}
	dataDir := opts.Config.DataDir
	if !filepath.IsAbs(dataDir) {
		return nil, errors.New("data directory must be absolute")
	}
	authURL := opts.OAuthAuthURL
	if authURL == "" {
		authURL = defaultAuthURL
	}
	tokenURL := opts.OAuthTokenURL
	if tokenURL == "" {
		tokenURL = defaultTokenURL
	}
	if err := checkEndpoint(authURL, false); err != nil {
		return nil, fmt.Errorf("authorization endpoint: %w", err)
	}
	if err := checkEndpoint(tokenURL, true); err != nil {
		return nil, fmt.Errorf("token endpoint: %w", err)
	}
	apiBase := opts.APIBaseURL
	if apiBase == "" {
		apiBase = olist.BaseURL
	}
	readSecret := opts.ReadSecret
	if readSecret == nil {
		readSecret = os.ReadFile
	}

	mirror, err := store.Open(ctx, filepath.Join(dataDir, "olist.db"))
	if err != nil {
		return nil, fmt.Errorf("open mirror: %w", err)
	}
	tokens, err := tokenstore.Open(filepath.Join(dataDir, "control.db"), opts.TokenKey)
	if err != nil {
		mirror.Close()
		return nil, fmt.Errorf("open token store: %w", err)
	}
	rt := &Runtime{mirror: mirror, tokens: tokens, accounts: map[string]*account{}}
	if err := rt.build(ctx, opts, authURL, tokenURL, apiBase, readSecret); err != nil {
		rt.Close()
		return nil, err
	}
	states, err := oauthstate.New(stateTTL, stateCapacity)
	if err != nil {
		rt.Close()
		return nil, err
	}
	rt.states = states
	h, err := admin.New(opts.OwnerAuth, rt.oauthConfig, states, tokens)
	if err != nil {
		rt.Close()
		return nil, err
	}
	rt.admin = h
	return rt, nil
}

func (rt *Runtime) build(ctx context.Context, opts Options, authURL, tokenURL, apiBase string, readSecret func(string) ([]byte, error)) error {
	redirect := strings.TrimRight(opts.Config.PublicURL, "/") + CallbackPath
	for _, a := range opts.Config.Accounts {
		raw, err := readSecret(a.ClientSecretFile)
		if err != nil {
			// The path is configuration, not a secret. The file contents never appear here.
			return fmt.Errorf("account %s: cannot read client secret file", a.ID)
		}
		secret := strings.TrimSpace(string(raw))
		if secret == "" {
			return fmt.Errorf("account %s: client secret file is empty", a.ID)
		}
		oc := oauth2.Config{
			ClientID:     a.ClientID,
			ClientSecret: secret,
			RedirectURL:  redirect,
			Endpoint: oauth2.Endpoint{
				AuthURL:   authURL,
				TokenURL:  tokenURL,
				AuthStyle: oauth2.AuthStyleInParams,
			},
		}
		manager, err := olistauth.New(a.ID, oc, rt.tokens)
		if err != nil {
			return fmt.Errorf("account %s: %w", a.ID, err)
		}
		limiter, err := ratelimit.New(a.ReadsPerMinute, reservedPercent)
		if err != nil {
			return fmt.Errorf("account %s: %w", a.ID, err)
		}
		client, err := olist.NewClient(apiBase, manager.AccessToken)
		if err != nil {
			return fmt.Errorf("account %s: %w", a.ID, err)
		}
		reader, err := olist.NewLimitedReader(client, limiter, false)
		if err != nil {
			return fmt.Errorf("account %s: %w", a.ID, err)
		}
		if err := rt.mirror.PutAccount(ctx, a.ID, a.DisplayName); err != nil {
			return fmt.Errorf("account %s: %w", a.ID, err)
		}
		rt.accounts[a.ID] = &account{id: a.ID, oauth: oc, tokens: manager, reader: reader, syncSlot: make(chan struct{}, 1)}
		rt.order = append(rt.order, a.ID)
	}
	if len(rt.accounts) == 0 {
		return errors.New("at least one account is required")
	}
	return nil
}

// oauthConfig selects the OAuth configuration for a configured account.
// Unknown accounts are refused, so the admin handlers cannot start a flow for them.
func (rt *Runtime) oauthConfig(id string) (oauth2.Config, bool) {
	a, ok := rt.accounts[id]
	if !ok {
		return oauth2.Config{}, false
	}
	return a.oauth, true
}

// checkEndpoint requires https, or loopback http when allowLoopbackHTTP is set.
func checkEndpoint(raw string, allowLoopbackHTTP bool) error {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return errors.New("must be an absolute URL without user information, query or fragment")
	}
	if u.Scheme == "https" {
		return nil
	}
	host := u.Hostname()
	if allowLoopbackHTTP && u.Scheme == "http" && (host == "127.0.0.1" || host == "localhost" || host == "::1") {
		return nil
	}
	return errors.New("must use https")
}

// Accounts lists the configured account IDs in configuration order.
func (rt *Runtime) Accounts() []string {
	return append([]string(nil), rt.order...)
}

// Admin returns the owner-protected connection handlers. Mount them behind
// authentication only; this package does not mount them.
func (rt *Runtime) Admin() *admin.Handler {
	return rt.admin
}

// Mirror returns the mirror store, for read-only inspection by callers.
func (rt *Runtime) Mirror() *store.Store {
	return rt.mirror
}

// Jobs returns the tracked sync jobs for one account, in dependency order:
// products, then contacts, then orders. Each job records its coverage.
func (rt *Runtime) Jobs(accountID string) ([]scheduler.Job, error) {
	a, ok := rt.accounts[accountID]
	if !ok {
		return nil, fmt.Errorf("unknown account %q", accountID)
	}
	type spec struct {
		resource, class string
		run             func(context.Context) error
	}
	specs := []spec{
		{"produtos", "list", func(ctx context.Context) error {
			_, err := syncer.Products(ctx, a.reader, rt.mirror, a.id)
			return err
		}},
		{"contatos", "list", func(ctx context.Context) error {
			_, err := syncer.Contacts(ctx, a.reader, rt.mirror, a.id)
			return err
		}},
		{"pedidos", "list", func(ctx context.Context) error {
			_, err := syncer.Orders(ctx, a.reader, rt.mirror, a.id)
			return err
		}},
	}
	jobs := make([]scheduler.Job, 0, len(specs))
	for _, s := range specs {
		job, err := scheduler.TrackedJob(a.id, s.resource, s.class, rt.mirror, s.run)
		if err != nil {
			return nil, err
		}
		jobs = append(jobs, job)
	}
	return jobs, nil
}

// SyncOnce runs one account's jobs in order and returns the joined errors. A
// failed job does not stop the others. Unknown accounts are refused.
func (rt *Runtime) SyncOnce(ctx context.Context, accountID string) error {
	a, ok := rt.accounts[accountID]
	if !ok {
		return fmt.Errorf("unknown account %q", accountID)
	}
	select {
	case a.syncSlot <- struct{}{}:
		defer func() { <-a.syncSlot }()
	case <-ctx.Done():
		return ctx.Err()
	}
	jobs, err := rt.Jobs(accountID)
	if err != nil {
		return err
	}
	var errs []error
	for _, j := range jobs {
		if err := ctx.Err(); err != nil {
			return errors.Join(append(errs, err)...)
		}
		if err := j.Run(ctx); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", j.Name, err))
		}
	}
	return errors.Join(errs...)
}

// Close releases both databases.
func (rt *Runtime) Close() error {
	var errs []error
	if rt.tokens != nil {
		errs = append(errs, rt.tokens.Close())
	}
	if rt.mirror != nil {
		errs = append(errs, rt.mirror.Close())
	}
	return errors.Join(errs...)
}
