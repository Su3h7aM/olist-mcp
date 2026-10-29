package clientregistry

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func testRegistry(t *testing.T) (*Registry, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "clients.db")
	r, err := Open(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { r.Close() })
	return r, path
}

func TestOpenRequiresAbsolutePath(t *testing.T) {
	if _, err := Open(context.Background(), "clients.db"); err == nil {
		t.Fatal("relative path accepted")
	}
}

func TestCreateDefaultsToUnapproved(t *testing.T) {
	ctx := context.Background()
	r, _ := testRegistry(t)
	c, err := r.Create(ctx, "client-1", []string{"https://app.example/callback"})
	if err != nil {
		t.Fatal(err)
	}
	if c.Approved {
		t.Fatal("new client returned as approved")
	}
	got, err := r.Get(ctx, "client-1")
	if err != nil {
		t.Fatal(err)
	}
	if got.Approved {
		t.Fatal("stored client is approved by default")
	}
	if got.CreatedAt.IsZero() {
		t.Fatal("creation time not stored")
	}
}

func TestApprovalIsExplicitAndIdempotent(t *testing.T) {
	ctx := context.Background()
	r, _ := testRegistry(t)
	if _, err := r.Create(ctx, "client-1", []string{"https://app.example/cb"}); err != nil {
		t.Fatal(err)
	}
	if err := r.Approve(ctx, "client-1"); err != nil {
		t.Fatal(err)
	}
	if err := r.Approve(ctx, "client-1"); err != nil {
		t.Fatalf("second approval failed: %v", err)
	}
	got, _ := r.Get(ctx, "client-1")
	if !got.Approved {
		t.Fatal("approval not stored")
	}
	if err := r.Approve(ctx, "missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("approving unknown client: %v", err)
	}
}

func TestCreateNeverAutoApprovesOtherClients(t *testing.T) {
	ctx := context.Background()
	r, _ := testRegistry(t)
	if _, err := r.Create(ctx, "a", []string{"https://a.example/cb"}); err != nil {
		t.Fatal(err)
	}
	if err := r.Approve(ctx, "a"); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Create(ctx, "b", []string{"https://b.example/cb"}); err != nil {
		t.Fatal(err)
	}
	b, _ := r.Get(ctx, "b")
	if b.Approved {
		t.Fatal("approving one client approved another")
	}
}

func TestDuplicateIDRejectedAndOriginalUnchanged(t *testing.T) {
	ctx := context.Background()
	r, _ := testRegistry(t)
	if _, err := r.Create(ctx, "client-1", []string{"https://one.example/cb"}); err != nil {
		t.Fatal(err)
	}
	if err := r.Approve(ctx, "client-1"); err != nil {
		t.Fatal(err)
	}
	_, err := r.Create(ctx, "client-1", []string{"https://two.example/cb"})
	if !errors.Is(err, ErrDuplicate) {
		t.Fatalf("duplicate ID err = %v, want ErrDuplicate", err)
	}
	got, _ := r.Get(ctx, "client-1")
	if got.RedirectURIs[0] != "https://one.example/cb" || !got.Approved {
		t.Fatalf("duplicate create overwrote the original client: %+v", got)
	}
}

func TestInvalidIDsRejected(t *testing.T) {
	ctx := context.Background()
	r, _ := testRegistry(t)
	cases := []string{"", " ", "has space", "slash/id", "emoji-😀", "a\x00b", strings.Repeat("x", 129)}
	for _, id := range cases {
		if _, err := r.Create(ctx, id, []string{"https://app.example/cb"}); err == nil {
			t.Fatalf("ID %q accepted", id)
		}
	}
	if _, err := r.Create(ctx, strings.Repeat("x", 128), []string{"https://app.example/cb"}); err != nil {
		t.Fatalf("128-character ID rejected: %v", err)
	}
}

func TestEmptyRedirectListRejected(t *testing.T) {
	ctx := context.Background()
	r, _ := testRegistry(t)
	for _, uris := range [][]string{nil, {}} {
		if _, err := r.Create(ctx, "client-1", uris); err == nil {
			t.Fatal("empty redirect list accepted")
		}
	}
	if _, err := r.Get(ctx, "client-1"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("rejected client was stored: %v", err)
	}
}

func TestInvalidRedirectURIsRejected(t *testing.T) {
	ctx := context.Background()
	r, _ := testRegistry(t)
	cases := map[string][]string{
		"empty entry":       {""},
		"relative":          {"/callback"},
		"no host":           {"https:///callback"},
		"http non-loopback": {"http://app.example/callback"},
		"fragment":          {"https://app.example/cb#x"},
		"user info":         {"https://user:pw@app.example/cb"},
		"javascript":        {"javascript:alert(1)"},
		"duplicate entries": {"https://app.example/cb", "https://app.example/cb"},
	}
	for name, uris := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := r.Create(ctx, "client-"+strings.ReplaceAll(name, " ", "-"), uris); err == nil {
				t.Fatalf("%v accepted", uris)
			}
		})
	}
}

func TestLoopbackHTTPRedirectsAccepted(t *testing.T) {
	ctx := context.Background()
	r, _ := testRegistry(t)
	uris := []string{"http://127.0.0.1:8123/cb", "http://localhost/cb", "http://[::1]:9000/cb", "https://app.example/cb"}
	if _, err := r.Create(ctx, "local", uris); err != nil {
		t.Fatalf("loopback and https redirects rejected: %v", err)
	}
}

func TestRedirectListPreservedExactly(t *testing.T) {
	ctx := context.Background()
	r, _ := testRegistry(t)
	uris := []string{
		"https://app.example/callback",
		"https://app.example/callback/",
		"https://app.example/callback?lang=pt",
		"https://APP.example/Callback",
		"http://localhost:8123/cb",
	}
	if _, err := r.Create(ctx, "client-1", uris); err != nil {
		t.Fatal(err)
	}
	got, err := r.Get(ctx, "client-1")
	if err != nil {
		t.Fatal(err)
	}
	if len(got.RedirectURIs) != len(uris) {
		t.Fatalf("got %d URIs, want %d", len(got.RedirectURIs), len(uris))
	}
	for i := range uris {
		if got.RedirectURIs[i] != uris[i] {
			t.Fatalf("URI %d = %q, want %q (exact match required)", i, got.RedirectURIs[i], uris[i])
		}
	}
}

func TestCallerSliceIsNotAliased(t *testing.T) {
	ctx := context.Background()
	r, _ := testRegistry(t)
	uris := []string{"https://app.example/cb"}
	c, err := r.Create(ctx, "client-1", uris)
	if err != nil {
		t.Fatal(err)
	}
	uris[0] = "https://evil.example/cb"
	c.RedirectURIs[0] = "https://evil.example/cb"
	got, _ := r.Get(ctx, "client-1")
	if got.RedirectURIs[0] != "https://app.example/cb" {
		t.Fatal("stored redirect list changed through a caller's slice")
	}
}

func TestGetUnknownAndEmptyID(t *testing.T) {
	r, _ := testRegistry(t)
	if _, err := r.Get(context.Background(), "nope"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown ID err = %v", err)
	}
	if _, err := r.Get(context.Background(), ""); !errors.Is(err, ErrNotFound) {
		t.Fatalf("empty ID err = %v", err)
	}
}

func TestRestartPreservesClientsAndApproval(t *testing.T) {
	ctx := context.Background()
	r, path := testRegistry(t)
	if _, err := r.Create(ctx, "pending", []string{"https://p.example/cb"}); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Create(ctx, "approved", []string{"https://a.example/cb", "http://127.0.0.1/cb"}); err != nil {
		t.Fatal(err)
	}
	if err := r.Approve(ctx, "approved"); err != nil {
		t.Fatal(err)
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	p, err := reopened.Get(ctx, "pending")
	if err != nil || p.Approved {
		t.Fatalf("pending client after restart: %+v, %v", p, err)
	}
	a, err := reopened.Get(ctx, "approved")
	if err != nil || !a.Approved || len(a.RedirectURIs) != 2 || a.RedirectURIs[1] != "http://127.0.0.1/cb" {
		t.Fatalf("approved client after restart: %+v, %v", a, err)
	}
	if _, err := reopened.Create(ctx, "pending", []string{"https://x.example/cb"}); !errors.Is(err, ErrDuplicate) {
		t.Fatalf("duplicate after restart not rejected: %v", err)
	}
}

func TestCreatedAtUsesInjectedClock(t *testing.T) {
	ctx := context.Background()
	fixed := time.Date(2026, 10, 31, 9, 15, 0, 123456789, time.UTC)
	r, err := openWithClock(ctx, filepath.Join(t.TempDir(), "clients.db"), func() time.Time { return fixed })
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if _, err := r.Create(ctx, "client-1", []string{"https://app.example/cb"}); err != nil {
		t.Fatal(err)
	}
	got, _ := r.Get(ctx, "client-1")
	if !got.CreatedAt.Equal(fixed) {
		t.Fatalf("created at = %v, want %v", got.CreatedAt, fixed)
	}
}

func TestConcurrentCreateOfSameIDSucceedsOnce(t *testing.T) {
	ctx := context.Background()
	r, _ := testRegistry(t)
	var wins atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := r.Create(ctx, "race", []string{"https://app.example/cb"}); err == nil {
				wins.Add(1)
			} else if !errors.Is(err, ErrDuplicate) {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if n := wins.Load(); n != 1 {
		t.Fatalf("%d creates succeeded; want exactly 1", n)
	}
}

func TestConcurrentApproveAndGet(t *testing.T) {
	ctx := context.Background()
	r, _ := testRegistry(t)
	if _, err := r.Create(ctx, "client-1", []string{"https://app.example/cb"}); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 40; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			if err := r.Approve(ctx, "client-1"); err != nil {
				t.Error(err)
			}
		}()
		go func() {
			defer wg.Done()
			if _, err := r.Get(ctx, "client-1"); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	got, _ := r.Get(ctx, "client-1")
	if !got.Approved {
		t.Fatal("client not approved after concurrent approvals")
	}
}

func TestNoSecretColumns(t *testing.T) {
	ctx := context.Background()
	r, _ := testRegistry(t)
	if _, err := r.Create(ctx, "client-1", []string{"https://app.example/cb"}); err != nil {
		t.Fatal(err)
	}
	rows, err := r.db.QueryContext(ctx, `SELECT name FROM pragma_table_info('oauth_clients')`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var cols []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			t.Fatal(err)
		}
		cols = append(cols, name)
	}
	want := "client_id,redirect_uris,created_at,approved"
	if got := strings.Join(cols, ","); got != want {
		t.Fatalf("columns = %s, want %s", got, want)
	}
}
