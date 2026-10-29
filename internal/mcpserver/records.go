package mcpserver

import (
	"context"
	"encoding/json"
	"errors"
	"slices"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/openbot/olist-mcp/internal/store"
)

type Mirror interface {
	List(context.Context, string, string, int, int) ([]store.Record, error)
}
type ListInput struct {
	Account  string `json:"account" jsonschema:"Account ID granted to this client"`
	Resource string `json:"resource" jsonschema:"One of produtos, contatos or pedidos"`
	Limit    int    `json:"limit" jsonschema:"Page size from 1 to 100"`
	Offset   int    `json:"offset" jsonschema:"Zero-based page offset"`
}
type Item struct {
	ID         string `json:"id"`
	Payload    any    `json:"payload"`
	ObservedAt string `json:"observed_at"`
}
type ListOutput struct {
	Account  string `json:"account"`
	Resource string `json:"resource"`
	Items    []Item `json:"items"`
}

// NewWithMirror registers scoped reads. The verified token must carry the
// server-side grant as Extra["accounts"] of type []string, not user input.
func NewWithMirror(db Mirror) (*mcp.Server, error) {
	if db == nil {
		return nil, errors.New("mirror required")
	}
	s := New()
	mcp.AddTool(s, &mcp.Tool{Name: "list_records", Description: "List locally mirrored records for a granted account."}, func(ctx context.Context, req *mcp.CallToolRequest, in ListInput) (*mcp.CallToolResult, ListOutput, error) {
		out := ListOutput{}
		if req.Extra == nil || req.Extra.TokenInfo == nil {
			return nil, out, errors.New("account access denied")
		}
		accounts, ok := req.Extra.TokenInfo.Extra["accounts"].([]string)
		if !ok || !slices.Contains(accounts, in.Account) {
			return nil, out, errors.New("account access denied")
		}
		if in.Resource != "produtos" && in.Resource != "contatos" && in.Resource != "pedidos" {
			return nil, out, errors.New("unsupported resource")
		}
		if in.Limit < 1 || in.Limit > 100 || in.Offset < 0 {
			return nil, out, errors.New("invalid pagination")
		}
		rows, err := db.List(ctx, in.Account, in.Resource, in.Limit, in.Offset)
		if err != nil {
			return nil, out, errors.New("mirror query failed")
		}
		out.Account = in.Account
		out.Resource = in.Resource
		out.Items = make([]Item, 0, len(rows))
		for _, r := range rows {
			var payload any
			if err := json.Unmarshal(r.Payload, &payload); err != nil {
				return nil, ListOutput{}, errors.New("invalid mirror record")
			}
			out.Items = append(out.Items, Item{r.RemoteID, payload, r.ObservedAt.Format("2006-01-02T15:04:05.999999999Z07:00")})
		}
		return nil, out, nil
	})
	return s, nil
}
