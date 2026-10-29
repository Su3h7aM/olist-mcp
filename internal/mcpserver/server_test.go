package mcpserver

import (
	"context"
	"net/http/httptest"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func connect(t *testing.T) *mcp.ClientSession {
	t.Helper()
	ts := httptest.NewServer(Handler())
	t.Cleanup(ts.Close)

	client := mcp.NewClient(&mcp.Implementation{Name: "test-client", Version: "0.0.1"}, nil)
	session, err := client.Connect(context.Background(), &mcp.StreamableClientTransport{Endpoint: ts.URL}, nil)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(func() { session.Close() })
	return session
}

func TestInitialize(t *testing.T) {
	session := connect(t)

	res := session.InitializeResult()
	if res.ServerInfo == nil || res.ServerInfo.Name != serverName {
		t.Fatalf("server info = %+v, want name %q", res.ServerInfo, serverName)
	}
	if res.Capabilities == nil || res.Capabilities.Tools == nil {
		t.Fatal("server did not advertise the tools capability")
	}
}

func TestListToolsIncludesDiagnostics(t *testing.T) {
	session := connect(t)

	res, err := session.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatalf("tools/list: %v", err)
	}
	var found bool
	for _, tool := range res.Tools {
		if tool.Name == diagnosticTool {
			found = true
		}
	}
	if len(res.Tools) != 1 || !found {
		t.Fatalf("tools = %+v, want only %q", res.Tools, diagnosticTool)
	}
}

func TestDiagnosticsToolReturnsPrototypeMetadata(t *testing.T) {
	session := connect(t)

	res, err := session.CallTool(context.Background(), &mcp.CallToolParams{Name: diagnosticTool, Arguments: map[string]any{}})
	if err != nil {
		t.Fatalf("tools/call: %v", err)
	}
	if res.IsError {
		t.Fatalf("tool returned error: %+v", res.Content)
	}
	if res.StructuredContent == nil {
		t.Fatal("no structured content")
	}
	out, ok := res.StructuredContent.(map[string]any)
	if !ok {
		t.Fatalf("structured content type = %T", res.StructuredContent)
	}
	if out["status"] != "ok" || out["prototype"] != true {
		t.Fatalf("diagnostics = %+v", out)
	}
	if _, ok := out["accounts"]; ok {
		t.Fatal("diagnostics must not expose account data")
	}
}
