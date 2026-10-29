// Package admin implements account connection handlers for authenticated owners.
package admin

import (
	"errors"
	"net/http"
	"net/url"
	"strings"

	"github.com/openbot/olist-mcp/internal/oauthstate"
	"github.com/openbot/olist-mcp/internal/olistauth"
	"golang.org/x/oauth2"
)

// Owner resolves a verified owner identity. It must reject unauthenticated
// requests and enforce CSRF protection for POST requests before returning.
type Owner func(*http.Request) (string, error)
type AccountConfig func(string) (oauth2.Config, bool)
type Handler struct {
	owner   Owner
	configs AccountConfig
	state   *oauthstate.Registry
	store   olistauth.TokenStore
}

func New(owner Owner, configs AccountConfig, state *oauthstate.Registry, store olistauth.TokenStore) (*Handler, error) {
	if owner == nil || configs == nil || state == nil || store == nil {
		return nil, errors.New("authenticated owner, account configuration, state and store required")
	}
	return &Handler{owner, configs, state, store}, nil
}

// Start accepts POST only. The authenticated owner selects an existing account.
func (h *Handler) Start(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	owner, err := h.owner(r)
	if err != nil || owner == "" {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	if err = r.ParseForm(); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	account := r.PostForm.Get("account")
	cfg, ok := h.configs(account)
	if !ok {
		http.Error(w, "unknown account", http.StatusBadRequest)
		return
	}
	state, err := h.state.Issue(owner, account)
	if err != nil {
		http.Error(w, "cannot start authorization", http.StatusServiceUnavailable)
		return
	}
	target, err := olistauth.AuthorizationURL(cfg, state)
	if err != nil {
		http.Error(w, "authorization unavailable", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, target, http.StatusSeeOther)
}

// Callback validates and consumes state before exchanging the code. It must be
// mounted behind the same owner authentication as Start.
func (h *Handler) Callback(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	owner, err := h.owner(r)
	if err != nil || owner == "" {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	q := r.URL.Query()
	if !single(q, "state") || !single(q, "code") {
		http.Error(w, "invalid callback", http.StatusBadRequest)
		return
	}
	account, err := h.state.Consume(q.Get("state"), owner)
	if err != nil {
		http.Error(w, "invalid authorization state", http.StatusBadRequest)
		return
	}
	cfg, ok := h.configs(account)
	if !ok {
		http.Error(w, "unknown account", http.StatusBadRequest)
		return
	}
	if err = olistauth.Exchange(r.Context(), cfg, h.store, account, q.Get("code")); err != nil {
		http.Error(w, "account connection failed", http.StatusBadGateway)
		return
	}
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Account connected. You may close this page."))
}
func single(q url.Values, k string) bool { return len(q[k]) == 1 && strings.TrimSpace(q[k][0]) != "" }
