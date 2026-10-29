package mcpserver

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/auth"
	"github.com/modelcontextprotocol/go-sdk/oauthex"
)

// Protected returns MCP and metadata handlers using an externally supplied
// verifier. The verifier must validate issuer, audience, grant and revocation;
// it must not expose credentials in its errors. This does not create an OAuth server.
func Protected(publicURL string, verifier auth.TokenVerifier) (http.Handler, http.Handler, error) {
	u, err := url.Parse(publicURL)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") || verifier == nil {
		return nil, nil, errors.New("HTTPS public origin and token verifier required")
	}
	origin := strings.TrimRight(u.String(), "/")
	resource := origin + "/mcp"
	metadataURL := origin + "/.well-known/oauth-protected-resource/mcp"
	// Prevent verifier errors from leaking credentials or provider responses.
	safe := func(ctx context.Context, token string, r *http.Request) (*auth.TokenInfo, error) {
		info, err := verifier(ctx, token, r)
		if err != nil {
			return nil, auth.ErrInvalidToken
		}
		return info, nil
	}
	middleware := auth.RequireBearerToken(safe, &auth.RequireBearerTokenOptions{ResourceMetadataURL: metadataURL, Scopes: []string{"olist:read"}})
	metadata := auth.ProtectedResourceMetadataHandler(&oauthex.ProtectedResourceMetadata{Resource: resource, AuthorizationServers: []string{origin}, ScopesSupported: []string{"olist:read", "olist:write"}, BearerMethodsSupported: []string{"header"}})
	return middleware(Handler()), metadata, nil
}
