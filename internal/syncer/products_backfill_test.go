package syncer

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/openbot/olist-mcp/internal/olist"
	"github.com/openbot/olist-mcp/internal/store"
)

// fakeTiny serves a paginated product list of ids 1..total and a detail
// endpoint. Hooks let a test inject failures or malformed bodies.
type fakeTiny struct {
	t     *testing.T
	total int
	tag   string // included in detail payloads so accounts can be told apart

	mu          sync.Mutex
	listOffsets []int
	detailIDs   []int
	detailFail  map[int]int // id -> HTTP status for detail
	listBody    func(offset int) (string, bool)
	detailBody  func(id int) (string, bool)
	cancelAt    int // detail request number at which to cancel cancelFn and hang
	cancelFn    context.CancelFunc
}

func (f *fakeTiny) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if r.Header.Get("Authorization") == "" {
		f.t.Error("request without authorization")
	}
	switch {
	case r.URL.Path == "/produtos":
		if r.URL.Query().Get("limit") != "100" {
			f.t.Errorf("limit = %q, want 100", r.URL.Query().Get("limit"))
		}
		offset, err := strconv.Atoi(r.URL.Query().Get("offset"))
		if err != nil {
			f.t.Errorf("offset = %q", r.URL.Query().Get("offset"))
		}
		f.listOffsets = append(f.listOffsets, offset)
		if f.listBody != nil {
			if body, ok := f.listBody(offset); ok {
				w.Write([]byte(body))
				return
			}
		}
		w.Write([]byte(f.listPage(offset)))
	case strings.HasPrefix(r.URL.Path, "/produtos/"):
		id, err := strconv.Atoi(strings.TrimPrefix(r.URL.Path, "/produtos/"))
		if err != nil {
			f.t.Errorf("detail path %q", r.URL.Path)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		f.detailIDs = append(f.detailIDs, id)
		if f.cancelAt != 0 && len(f.detailIDs) == f.cancelAt {
			// Cancel the caller and hold the response until the client disconnects,
			// so the client cannot receive this body first.
			f.cancelFn()
			<-r.Context().Done()
			return
		}
		if status, ok := f.detailFail[id]; ok {
			w.WriteHeader(status)
			return
		}
		if f.detailBody != nil {
			if body, ok := f.detailBody(id); ok {
				w.Write([]byte(body))
				return
			}
		}
		fmt.Fprintf(w, `{"id":%d,"tag":%q}`, id, f.tag)
	default:
		f.t.Errorf("unexpected path %s", r.URL.Path)
		w.WriteHeader(http.StatusNotFound)
	}
}

// listPage returns the honest page for offset: ids offset+1..min(offset+100, total).
func (f *fakeTiny) listPage(offset int) string {
	var items []string
	for id := offset + 1; id <= f.total && id <= offset+100; id++ {
		items = append(items, fmt.Sprintf(`{"id":%d}`, id))
	}
	return fmt.Sprintf(`{"itens":[%s],"paginacao":{"limit":100,"offset":%d,"total":%d}}`,
		strings.Join(items, ","), offset, f.total)
}

func (f *fakeTiny) snapshot() (offsets, details []int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]int(nil), f.listOffsets...), append([]int(nil), f.detailIDs...)
}

func newFake(t *testing.T, total int) (*fakeTiny, *httptest.Server) {
	t.Helper()
	f := &fakeTiny{t: t, total: total, tag: "a", detailFail: map[int]int{}}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	return f, srv
}

// countingLimiter records every budget check and can deny after a number of calls.
type countingLimiter struct {
	mu        sync.Mutex
	calls     int
	onDemands []bool
	allow     int // calls permitted before denying; -1 means unlimited
}

func (l *countingLimiter) Wait(ctx context.Context, onDemand bool) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	if l.allow >= 0 && l.calls >= l.allow {
		return errors.New("budget exhausted")
	}
	l.calls++
	l.onDemands = append(l.onDemands, onDemand)
	return nil
}

func newReader(t *testing.T, base string, lim olist.ReadLimiter) *olist.LimitedReader {
	t.Helper()
	client, err := olist.NewClient(base, func(context.Context) (string, error) { return "token", nil })
	if err != nil {
		t.Fatal(err)
	}
	reader, err := olist.NewLimitedReader(client, lim, false)
	if err != nil {
		t.Fatal(err)
	}
	return reader
}

func newStore(t *testing.T, accounts ...string) *store.Store {
	t.Helper()
	ctx := context.Background()
	db, err := store.Open(ctx, filepath.Join(t.TempDir(), "olist.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	for _, a := range accounts {
		if err := db.PutAccount(ctx, a, a); err != nil {
			t.Fatal(err)
		}
	}
	return db
}

func storedCount(t *testing.T, db *store.Store, account string) int {
	t.Helper()
	recs, err := db.List(context.Background(), account, "produtos", 1000, 0)
	if err != nil {
		t.Fatal(err)
	}
	return len(recs)
}

func sameInts(got, want []int) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}

func seq(from, to int) []int {
	var out []int
	for i := from; i <= to; i++ {
		out = append(out, i)
	}
	return out
}

func TestBackfillThreePagesWithPartialLast(t *testing.T) {
	fake, srv := newFake(t, 250)
	lim := &countingLimiter{allow: -1}
	db := newStore(t, "a")

	p, err := Products(context.Background(), newReader(t, srv.URL, lim), db, "a")
	if err != nil {
		t.Fatalf("Products: %v", err)
	}
	if p.Pages != 3 || p.Records != 250 {
		t.Fatalf("progress = %+v, want 3 pages and 250 records", p)
	}
	offsets, details := fake.snapshot()
	if !sameInts(offsets, []int{0, 100, 200}) {
		t.Fatalf("list offsets = %v, want [0 100 200]", offsets)
	}
	if !sameInts(details, seq(1, 250)) {
		t.Fatalf("detail requests = %d, want ids 1..250 in order", len(details))
	}
	if n := storedCount(t, db, "a"); n != 250 {
		t.Fatalf("stored = %d, want 250", n)
	}
	r, err := db.Get(context.Background(), "a", "produtos", "250")
	if err != nil || string(r.Payload) != `{"id":250,"tag":"a"}` {
		t.Fatalf("record 250 = %s, %v", r.Payload, err)
	}
	// Every list and detail call goes through the account's limiter, as background reads.
	if lim.calls != 3+250 {
		t.Fatalf("limiter calls = %d, want %d", lim.calls, 3+250)
	}
	for _, onDemand := range lim.onDemands {
		if onDemand {
			t.Fatal("backfill issued an on-demand read")
		}
	}
}

func TestBackfillExactMultipleStopsWithoutExtraList(t *testing.T) {
	fake, srv := newFake(t, 200)
	db := newStore(t, "a")

	p, err := Products(context.Background(), newReader(t, srv.URL, &countingLimiter{allow: -1}), db, "a")
	if err != nil {
		t.Fatal(err)
	}
	offsets, _ := fake.snapshot()
	if p.Pages != 2 || p.Records != 200 || !sameInts(offsets, []int{0, 100}) {
		t.Fatalf("progress = %+v offsets = %v; want 2 pages, 200 records, no third list call", p, offsets)
	}
}

func TestBackfillEmptyCatalog(t *testing.T) {
	fake, srv := newFake(t, 0)
	db := newStore(t, "a")

	p, err := Products(context.Background(), newReader(t, srv.URL, &countingLimiter{allow: -1}), db, "a")
	if err != nil {
		t.Fatal(err)
	}
	offsets, details := fake.snapshot()
	if p.Pages != 1 || p.Records != 0 || len(details) != 0 || !sameInts(offsets, []int{0}) {
		t.Fatalf("progress = %+v offsets = %v details = %v", p, offsets, details)
	}
}

func TestDetailFailureMidRunKeepsPartialAndRecovers(t *testing.T) {
	fake, srv := newFake(t, 250)
	fake.detailFail[150] = http.StatusInternalServerError
	db := newStore(t, "a")
	ctx := context.Background()

	_, err := Products(ctx, newReader(t, srv.URL, &countingLimiter{allow: -1}), db, "a")
	var httpErr *olist.HTTPError
	if !errors.As(err, &httpErr) || httpErr.StatusCode != http.StatusInternalServerError {
		t.Fatalf("err = %v, want HTTP 500 from detail", err)
	}
	if n := storedCount(t, db, "a"); n != 149 {
		t.Fatalf("stored after failure = %d, want 149 (ids before the failing detail)", n)
	}
	_, details := fake.snapshot()
	if len(details) != 150 || details[len(details)-1] != 150 {
		t.Fatalf("detail requests = %d, last = %v; want run to stop at id 150", len(details), details[len(details)-1])
	}

	// Restart with a healthy endpoint: the run completes and does not duplicate rows.
	fake.mu.Lock()
	delete(fake.detailFail, 150)
	fake.mu.Unlock()
	p, err := Products(ctx, newReader(t, srv.URL, &countingLimiter{allow: -1}), db, "a")
	if err != nil || p.Records != 250 {
		t.Fatalf("restart progress = %+v, err = %v", p, err)
	}
	if n := storedCount(t, db, "a"); n != 250 {
		t.Fatalf("stored after restart = %d, want 250 with no duplicates", n)
	}
}

func TestContextCancelStopsRequests(t *testing.T) {
	fake, srv := newFake(t, 250)
	db := newStore(t, "a")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	fake.cancelAt = 6 // the sixth detail request cancels the run and never completes
	fake.cancelFn = cancel

	_, err := Products(ctx, newReader(t, srv.URL, &countingLimiter{allow: -1}), db, "a")
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
	_, details := fake.snapshot()
	if len(details) != 6 {
		t.Fatalf("detail requests = %d, want 6 (no list or detail calls after cancel)", len(details))
	}
	if n := storedCount(t, db, "a"); n != 5 {
		t.Fatalf("stored = %d, want 5 committed before cancel", n)
	}
}

func TestPreCancelledContextSendsNothing(t *testing.T) {
	fake, srv := newFake(t, 250)
	db := newStore(t, "a")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := Products(ctx, newReader(t, srv.URL, &countingLimiter{allow: -1}), db, "a")
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
	offsets, details := fake.snapshot()
	if len(offsets) != 0 || len(details) != 0 {
		t.Fatalf("requests sent with cancelled context: list %v detail %d", offsets, len(details))
	}
}

func TestLimiterDenialStopsBeforeNetwork(t *testing.T) {
	fake, srv := newFake(t, 250)
	db := newStore(t, "a")
	// One list call plus nine details are allowed; the tenth detail is denied.
	lim := &countingLimiter{allow: 10}

	_, err := Products(context.Background(), newReader(t, srv.URL, lim), db, "a")
	if err == nil || !strings.Contains(err.Error(), "budget exhausted") {
		t.Fatalf("err = %v, want budget exhausted", err)
	}
	offsets, details := fake.snapshot()
	if len(offsets) != 1 || len(details) != 9 {
		t.Fatalf("server saw list %v and %d details; want 1 list and 9 details", offsets, len(details))
	}
	if n := storedCount(t, db, "a"); n != 9 {
		t.Fatalf("stored = %d, want 9", n)
	}
}

func TestMalformedPaginationRejected(t *testing.T) {
	cases := map[string]func(offset int) (string, bool){
		"offset mismatch": func(offset int) (string, bool) {
			return `{"itens":[{"id":1}],"paginacao":{"limit":100,"offset":7,"total":1}}`, true
		},
		"zero limit": func(offset int) (string, bool) {
			return `{"itens":[{"id":1}],"paginacao":{"limit":0,"offset":0,"total":1}}`, true
		},
		"negative total": func(offset int) (string, bool) {
			return `{"itens":[],"paginacao":{"limit":100,"offset":0,"total":-1}}`, true
		},
		"missing paginacao": func(offset int) (string, bool) {
			return `{"itens":[{"id":1}]}`, true
		},
		"null itens": func(offset int) (string, bool) {
			return `{"itens":null,"paginacao":{"limit":100,"offset":0,"total":1}}`, true
		},
		"non-JSON body": func(offset int) (string, bool) {
			return `<html>gateway</html>`, true
		},
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			fake, srv := newFake(t, 250)
			fake.listBody = body
			db := newStore(t, "a")

			if _, err := Products(context.Background(), newReader(t, srv.URL, &countingLimiter{allow: -1}), db, "a"); err == nil {
				t.Fatal("malformed list response accepted")
			}
			_, details := fake.snapshot()
			if len(details) != 0 || storedCount(t, db, "a") != 0 {
				t.Fatalf("details %d or stored rows written from a rejected page", len(details))
			}
		})
	}
}

func TestPaginationStallOnSecondPageRejected(t *testing.T) {
	fake, srv := newFake(t, 250)
	fake.listBody = func(offset int) (string, bool) {
		if offset == 100 {
			return `{"itens":[],"paginacao":{"limit":100,"offset":100,"total":250}}`, true
		}
		return "", false
	}
	db := newStore(t, "a")

	p, err := Products(context.Background(), newReader(t, srv.URL, &countingLimiter{allow: -1}), db, "a")
	if err == nil {
		t.Fatal("empty page before total accepted")
	}
	if p.Records != 100 || storedCount(t, db, "a") != 100 {
		t.Fatalf("progress = %+v, stored = %d; want first page only", p, storedCount(t, db, "a"))
	}
}

func TestMalformedIDsRejected(t *testing.T) {
	cases := map[string]string{
		"zero id":     `{"itens":[{"id":0}],"paginacao":{"limit":100,"offset":0,"total":1}}`,
		"negative id": `{"itens":[{"id":-3}],"paginacao":{"limit":100,"offset":0,"total":1}}`,
		"fractional":  `{"itens":[{"id":1.5}],"paginacao":{"limit":100,"offset":0,"total":1}}`,
		"missing id":  `{"itens":[{"sku":"A"}],"paginacao":{"limit":100,"offset":0,"total":1}}`,
		"null id":     `{"itens":[{"id":null}],"paginacao":{"limit":100,"offset":0,"total":1}}`,
		"boolean id":  `{"itens":[{"id":true}],"paginacao":{"limit":100,"offset":0,"total":1}}`,
		"alpha id":    `{"itens":[{"id":"abc"}],"paginacao":{"limit":100,"offset":0,"total":1}}`,
		"exponent id": `{"itens":[{"id":1e3}],"paginacao":{"limit":100,"offset":0,"total":1}}`,
		"overflow id": `{"itens":[{"id":99999999999999999999}],"paginacao":{"limit":100,"offset":0,"total":1}}`,
		"non-object":  `{"itens":[7],"paginacao":{"limit":100,"offset":0,"total":1}}`,
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			fake, srv := newFake(t, 1)
			fake.listBody = func(int) (string, bool) { return body, true }
			db := newStore(t, "a")

			if _, err := Products(context.Background(), newReader(t, srv.URL, &countingLimiter{allow: -1}), db, "a"); err == nil {
				t.Fatal("malformed product ID accepted")
			}
			_, details := fake.snapshot()
			if len(details) != 0 || storedCount(t, db, "a") != 0 {
				t.Fatalf("detail requests %d, stored %d; want none", len(details), storedCount(t, db, "a"))
			}
		})
	}
}

func TestBackfillIsScopedPerAccount(t *testing.T) {
	ctx := context.Background()
	fakeA, srvA := newFake(t, 250)
	fakeA.tag = "a"
	fakeB, srvB := newFake(t, 3)
	fakeB.tag = "b"
	db := newStore(t, "a", "b")
	limA := &countingLimiter{allow: -1}
	limB := &countingLimiter{allow: -1}

	if _, err := Products(ctx, newReader(t, srvA.URL, limA), db, "a"); err != nil {
		t.Fatal(err)
	}
	if _, err := Products(ctx, newReader(t, srvB.URL, limB), db, "b"); err != nil {
		t.Fatal(err)
	}

	if n := storedCount(t, db, "a"); n != 250 {
		t.Fatalf("account a stored = %d, want 250", n)
	}
	if n := storedCount(t, db, "b"); n != 3 {
		t.Fatalf("account b stored = %d, want 3", n)
	}
	// Remote ID 1 exists in both accounts and must keep each account's payload.
	ra, _ := db.Get(ctx, "a", "produtos", "1")
	rb, _ := db.Get(ctx, "b", "produtos", "1")
	if string(ra.Payload) != `{"id":1,"tag":"a"}` || string(rb.Payload) != `{"id":1,"tag":"b"}` {
		t.Fatalf("payloads = %s / %s; accounts bled into each other", ra.Payload, rb.Payload)
	}
	// Each account spent only its own budget.
	if limA.calls != 3+250 || limB.calls != 1+3 {
		t.Fatalf("limiter calls a=%d b=%d, want 253 and 4", limA.calls, limB.calls)
	}
	if _, details := fakeB.snapshot(); len(details) != 3 {
		t.Fatalf("account b server saw %d details, want 3", len(details))
	}
}

func TestProductsRequiresAccountAndDependencies(t *testing.T) {
	ctx := context.Background()
	db := newStore(t, "a")
	_, srv := newFake(t, 1)
	api := newReader(t, srv.URL, &countingLimiter{allow: -1})

	if _, err := Products(ctx, api, db, ""); err == nil {
		t.Error("empty account accepted")
	}
	if _, err := Products(ctx, nil, db, "a"); err == nil {
		t.Error("nil API accepted")
	}
	if _, err := Products(ctx, api, nil, "a"); err == nil {
		t.Error("nil store accepted")
	}
}

func TestUnregisteredAccountFailsAtStore(t *testing.T) {
	fake, srv := newFake(t, 2)
	db := newStore(t) // no accounts registered

	_, err := Products(context.Background(), newReader(t, srv.URL, &countingLimiter{allow: -1}), db, "ghost")
	if err == nil {
		t.Fatal("writes for an unregistered account succeeded")
	}
	if _, details := fake.snapshot(); len(details) != 1 {
		t.Fatalf("detail requests = %d, want 1 before the first write fails", len(details))
	}
}

func TestRejectInvalidPageBeforeWriting(t *testing.T) {
	for _, body := range []string{`{"itens":[{"id":1},{"id":2}],"paginacao":{"limit":100,"offset":0,"total":250}}`, `{"itens":[{"id":1},{"id":2}],"paginacao":{"limit":100,"offset":0,"total":1}}`} {
		fake, srv := newFake(t, 250)
		fake.listBody = func(int) (string, bool) { return body, true }
		db := newStore(t, "a")
		if _, err := Products(context.Background(), newReader(t, srv.URL, &countingLimiter{allow: -1}), db, "a"); err == nil {
			t.Fatal("invalid page accepted")
		}
		_, details := fake.snapshot()
		if len(details) != 0 || storedCount(t, db, "a") != 0 {
			t.Fatal("invalid page caused writes")
		}
	}
}
func TestRejectInvalidDetail(t *testing.T) {
	for _, body := range []string{`null`, `{"id":999}`, `{}`} {
		fake, srv := newFake(t, 1)
		fake.detailBody = func(int) (string, bool) { return body, true }
		db := newStore(t, "a")
		if _, err := Products(context.Background(), newReader(t, srv.URL, &countingLimiter{allow: -1}), db, "a"); err == nil {
			t.Fatal("invalid detail accepted")
		}
		if storedCount(t, db, "a") != 0 {
			t.Fatal("invalid detail stored")
		}
	}
}
