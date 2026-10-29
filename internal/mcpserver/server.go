// Package mcpserver exposes the Olist MCP over Streamable HTTP.
//
// PROTOTYPE, NOT FOR PRODUCTION: this package has no authentication, no
// authorization and no account scoping. It only offers a diagnostic tool
// that returns non-confidential server metadata. It must not be exposed
// on a public address until OAuth and grant checks are implemented.
package mcpserver

import (
	"context"
	"net/http"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const (
	serverName     = "olist-mcp"
	serverVersion  = "0.0.1-prototype"
	diagnosticTool = "olist_diagnostics"
)

// DiagnosticsInput takes no arguments.
type DiagnosticsInput struct{}

// DiagnosticsOutput holds only non-confidential server metadata.
type DiagnosticsOutput struct {
	Server     string `json:"server" jsonschema:"server name"`
	Version    string `json:"version" jsonschema:"prototype version"`
	Status     string `json:"status" jsonschema:"always ok while the process serves requests"`
	Prototype  bool   `json:"prototype" jsonschema:"true: this build is not safe for production"`
	ServerTime string `json:"server_time" jsonschema:"current UTC time, RFC3339"`
}

// New returns an MCP server with the diagnostic tool registered.
func New() *mcp.Server {
	s := mcp.NewServer(&mcp.Implementation{Name: serverName, Version: serverVersion}, nil)
	mcp.AddTool(s, &mcp.Tool{
		Name:        diagnosticTool,
		Description: "Returns non-confidential server metadata. Prototype only; no account data.",
	}, diagnostics)
	return s
}

func diagnostics(_ context.Context, _ *mcp.CallToolRequest, _ DiagnosticsInput) (*mcp.CallToolResult, DiagnosticsOutput, error) {
	return nil, DiagnosticsOutput{
		Server:     serverName,
		Version:    serverVersion,
		Status:     "ok",
		Prototype:  true,
		ServerTime: time.Now().UTC().Format(time.RFC3339),
	}, nil
}

// Handler serves the MCP Streamable HTTP endpoint. Mount it at a single
// path. The prototype has no authentication; see the package comment.
func Handler() http.Handler {
	s := New()
	return mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return s }, nil)
}
