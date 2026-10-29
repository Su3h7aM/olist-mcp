package syncer

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/openbot/olist-mcp/internal/olist"
	"github.com/openbot/olist-mcp/internal/store"
)

// orderTiny serves GET /pedidos (paged, ids 1..total) and GET /pedidos/{id}.
// Hooks inject failures and malformed bodies.
type orderTiny struct {
	t     *testing.T
	total int
	tag   string

	mu          sync.Mutex
	listOffsets []int
	detailIDs   []int
	detailFail  map[int]int
	listBody    func(offset int) (string, bool)
	detailBody  func(id int) (string, bool)
	cancelAt    int // detail request number that cancels cancelFn and never answers
	cancelFn    context.CancelFunc
}

func (f *orderTiny) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if r.Header.Get("Authorization") == "" {
		f.t.Error("request without authorization")
	}
	switch {
	case r.URL.Path == "/pedidos":
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
	case strings.HasPrefix(r.URL.Path, "/pedidos/"):
		id, err := strconv.Atoi(strings.TrimPrefix(r.URL.Path, "/pedidos/"))
		if err != nil {
			f.t.Errorf("detail path %q", r.URL.Path)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		f.detailIDs = append(f.detailIDs, id)
		if f.cancelAt != 0 && len(f.detailIDs) == f.cancelAt {
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
		fmt.Fprintf(w, `{"id":%d,"numeroPedido":%d,"tag":%q}`, id, id, f.tag)
	default:
		f.t.Errorf("unexpected path %s", r.URL.Path)
		w.WriteHeader(http.StatusNotFound)
	}
}

func (f *orderTiny) listPage(offset int) string {
	var items []string
	for id := offset + 1; id <= f.total && id <= offset+100; id++ {
		items = append(items, fmt.Sprintf(`{"id":%d,"numeroPedido":%d,"situacao":1}`, id, id))
	}
	return fmt.Sprintf(`{"itens":[%s],"paginacao":{"limit":100,"offset":%d,"total":%d}}`,
		strings.Join(items, ","), offset, f.total)
}

func (f *orderTiny) snapshot() (offsets, details []int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]int(nil), f.listOffsets...), append([]int(nil), f.detailIDs...)
}

func newOrderServer(t *testing.T, total int, tag string) (*orderTiny, *httptest.Server) {
	t.Helper()
	f := &orderTiny{t: t, total: total, tag: tag, detailFail: map[int]int{}}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	return f, srv
}

// orderLimiter counts budget checks and can deny after a number of calls.
type orderLimiter struct {
	mu        sync.Mutex
	calls     int
	onDemands []bool
	allow     int // -1 means unlimited
}

func (l *orderLimiter) Wait(ctx context.Context, onDemand bool) error {
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

func orderReader(t *testing.T, base string, lim olist.ReadLimiter) *olist.LimitedReader {
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

func orderStore(t *testing.T, accounts ...string) *store.Store {
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

func orderRows(t *testing.T, db *store.Store, account string) int {
	t.Helper()
	recs, err := db.List(context.Background(), account, "pedidos", 1000, 0)
	if err != nil {
		t.Fatal(err)
	}
	return len(recs)
}

func orderSeq(from, to int) []int {
	var out []int
	for i := from; i <= to; i++ {
		out = append(out, i)
	}
	return out
}

func orderEqualInts(got, want []int) bool {
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

func TestOrdersBackfillThreePagesWithPartialLast(t *testing.T) {
	fake, srv := newOrderServer(t, 250, "a")
	lim := &orderLimiter{allow: -1}
	db := orderStore(t, "a")

	p, err := Orders(context.Background(), orderReader(t, srv.URL, lim), db, "a")
	if err != nil {
		t.Fatalf("Orders: %v", err)
	}
	if p.Pages != 3 || p.Records != 250 {
		t.Fatalf("progress = %+v, want 3 pages and 250 records", p)
	}
	offsets, details := fake.snapshot()
	if !orderEqualInts(offsets, []int{0, 100, 200}) {
		t.Fatalf("list offsets = %v, want [0 100 200]", offsets)
	}
	if !orderEqualInts(details, orderSeq(1, 250)) {
		t.Fatalf("detail requests = %d, want ids 1..250 in order", len(details))
	}
	if n := orderRows(t, db, "a"); n != 250 {
		t.Fatalf("stored = %d, want 250", n)
	}
	r, err := db.Get(context.Background(), "a", "pedidos", "250")
	if err != nil || string(r.Payload) != `{"id":250,"numeroPedido":250,"tag":"a"}` {
		t.Fatalf("record 250 = %s, %v", r.Payload, err)
	}
	if lim.calls != 3+250 {
		t.Fatalf("limiter calls = %d, want %d", lim.calls, 3+250)
	}
	for _, onDemand := range lim.onDemands {
		if onDemand {
			t.Fatal("backfill issued an on-demand read")
		}
	}
}

func TestOrdersExactMultipleAndEmpty(t *testing.T) {
	ctx := context.Background()

	fake, srv := newOrderServer(t, 200, "a")
	db := orderStore(t, "a")
	p, err := Orders(ctx, orderReader(t, srv.URL, &orderLimiter{allow: -1}), db, "a")
	if err != nil {
		t.Fatal(err)
	}
	if offsets, _ := fake.snapshot(); p.Pages != 2 || p.Records != 200 || !orderEqualInts(offsets, []int{0, 100}) {
		t.Fatalf("progress = %+v offsets = %v; want 2 pages, no third list call", p, offsets)
	}

	fakeEmpty, srvEmpty := newOrderServer(t, 0, "a")
	dbEmpty := orderStore(t, "a")
	p, err = Orders(ctx, orderReader(t, srvEmpty.URL, &orderLimiter{allow: -1}), dbEmpty, "a")
	if err != nil {
		t.Fatal(err)
	}
	offsets, details := fakeEmpty.snapshot()
	if p.Pages != 1 || p.Records != 0 || len(details) != 0 || !orderEqualInts(offsets, []int{0}) {
		t.Fatalf("empty progress = %+v offsets = %v details = %v", p, offsets, details)
	}
}

func TestOrderDetailFailureMidRunKeepsPartialAndRecovers(t *testing.T) {
	ctx := context.Background()
	fake, srv := newOrderServer(t, 250, "a")
	fake.detailFail[150] = http.StatusInternalServerError
	db := orderStore(t, "a")

	_, err := Orders(ctx, orderReader(t, srv.URL, &orderLimiter{allow: -1}), db, "a")
	var httpErr *olist.HTTPError
	if !errors.As(err, &httpErr) || httpErr.StatusCode != http.StatusInternalServerError {
		t.Fatalf("err = %v, want HTTP 500 from detail", err)
	}
	if n := orderRows(t, db, "a"); n != 149 {
		t.Fatalf("stored after failure = %d, want 149", n)
	}

	fake.mu.Lock()
	delete(fake.detailFail, 150)
	fake.mu.Unlock()
	p, err := Orders(ctx, orderReader(t, srv.URL, &orderLimiter{allow: -1}), db, "a")
	if err != nil || p.Records != 250 {
		t.Fatalf("restart progress = %+v, err = %v", p, err)
	}
	if n := orderRows(t, db, "a"); n != 250 {
		t.Fatalf("stored after restart = %d, want 250 with no duplicates", n)
	}
}

func TestOrderDetailMismatchRejectedBeforeWrite(t *testing.T) {
	cases := map[string]func(id int) (string, bool){
		"wrong id": func(id int) (string, bool) {
			return `{"id":999,"numeroPedido":3}`, id == 2
		},
		"null body": func(id int) (string, bool) {
			return `null`, id == 2
		},
		"missing id": func(id int) (string, bool) {
			return `{"numeroPedido":7}`, id == 2
		},
		"string id": func(id int) (string, bool) {
			return `{"id":"2"}`, id == 2
		},
		"array body": func(id int) (string, bool) {
			return `[2]`, id == 2
		},
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			fake, srv := newOrderServer(t, 3, "a")
			fake.detailBody = body
			db := orderStore(t, "a")

			if _, err := Orders(context.Background(), orderReader(t, srv.URL, &orderLimiter{allow: -1}), db, "a"); err == nil {
				t.Fatal("mismatched or malformed detail accepted")
			}
			if n := orderRows(t, db, "a"); n != 1 {
				t.Fatalf("stored = %d, want 1 (only id 1 before the bad detail)", n)
			}
			if _, err := db.Get(context.Background(), "a", "pedidos", "2"); err == nil {
				t.Fatal("record stored under the requested id despite mismatch")
			}
			if _, err := db.Get(context.Background(), "a", "pedidos", "999"); err == nil {
				t.Fatal("mismatched payload stored under its own id")
			}
		})
	}
}

func TestMalformedOrderIDsRejectedBeforeAnyWrite(t *testing.T) {
	cases := map[string]string{
		"zero id":     `{"itens":[{"id":1},{"id":0}],"paginacao":{"limit":100,"offset":0,"total":2}}`,
		"negative id": `{"itens":[{"id":1},{"id":-3}],"paginacao":{"limit":100,"offset":0,"total":2}}`,
		"string id":   `{"itens":[{"id":1},{"id":"x"}],"paginacao":{"limit":100,"offset":0,"total":2}}`,
		"missing id":  `{"itens":[{"id":1},{"numeroPedido":7}],"paginacao":{"limit":100,"offset":0,"total":2}}`,
		"null id":     `{"itens":[{"id":1},{"id":null}],"paginacao":{"limit":100,"offset":0,"total":2}}`,
		"fractional":  `{"itens":[{"id":1},{"id":1.5}],"paginacao":{"limit":100,"offset":0,"total":2}}`,
		"overflow":    `{"itens":[{"id":1},{"id":99999999999999999999}],"paginacao":{"limit":100,"offset":0,"total":2}}`,
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			fake, srv := newOrderServer(t, 2, "a")
			fake.listBody = func(int) (string, bool) { return body, true }
			db := orderStore(t, "a")

			if _, err := Orders(context.Background(), orderReader(t, srv.URL, &orderLimiter{allow: -1}), db, "a"); err == nil {
				t.Fatal("malformed order ID accepted")
			}
			if _, details := fake.snapshot(); len(details) != 0 || orderRows(t, db, "a") != 0 {
				t.Fatalf("details %d and stored rows %d from a page with a bad ID; want none", len(details), orderRows(t, db, "a"))
			}
		})
	}
}

func TestMalformedOrderPaginationRejected(t *testing.T) {
	cases := map[string]func(offset int) (string, bool){
		"offset mismatch": func(int) (string, bool) {
			return `{"itens":[{"id":1}],"paginacao":{"limit":100,"offset":7,"total":1}}`, true
		},
		"limit mismatch": func(int) (string, bool) {
			return `{"itens":[{"id":1}],"paginacao":{"limit":50,"offset":0,"total":1}}`, true
		},
		"zero limit": func(int) (string, bool) {
			return `{"itens":[{"id":1}],"paginacao":{"limit":0,"offset":0,"total":1}}`, true
		},
		"negative total": func(int) (string, bool) {
			return `{"itens":[],"paginacao":{"limit":100,"offset":0,"total":-1}}`, true
		},
		"items beyond total": func(int) (string, bool) {
			return `{"itens":[{"id":1},{"id":2}],"paginacao":{"limit":100,"offset":0,"total":1}}`, true
		},
		"missing paginacao": func(int) (string, bool) {
			return `{"itens":[{"id":1}]}`, true
		},
		"null itens": func(int) (string, bool) {
			return `{"itens":null,"paginacao":{"limit":100,"offset":0,"total":1}}`, true
		},
		"non-JSON body": func(int) (string, bool) {
			return `<html>gateway</html>`, true
		},
		"short page before total": func(int) (string, bool) {
			return `{"itens":[{"id":1},{"id":2}],"paginacao":{"limit":100,"offset":0,"total":250}}`, true
		},
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			fake, srv := newOrderServer(t, 250, "a")
			fake.listBody = body
			db := orderStore(t, "a")

			if _, err := Orders(context.Background(), orderReader(t, srv.URL, &orderLimiter{allow: -1}), db, "a"); err == nil {
				t.Fatal("malformed order list response accepted")
			}
			if _, details := fake.snapshot(); len(details) != 0 || orderRows(t, db, "a") != 0 {
				t.Fatalf("details %d and stored rows %d from a rejected page; want none", len(details), orderRows(t, db, "a"))
			}
		})
	}
}

func TestOrderEmptyPageBeforeTotalStopsAfterFirstPage(t *testing.T) {
	fake, srv := newOrderServer(t, 250, "a")
	fake.listBody = func(offset int) (string, bool) {
		if offset == 100 {
			return `{"itens":[],"paginacao":{"limit":100,"offset":100,"total":250}}`, true
		}
		return "", false
	}
	db := orderStore(t, "a")

	p, err := Orders(context.Background(), orderReader(t, srv.URL, &orderLimiter{allow: -1}), db, "a")
	if err == nil {
		t.Fatal("empty page before total accepted")
	}
	if p.Records != 100 || orderRows(t, db, "a") != 100 {
		t.Fatalf("progress = %+v, stored = %d; want first page only", p, orderRows(t, db, "a"))
	}
}

func TestOrderContextCancelStopsRequests(t *testing.T) {
	fake, srv := newOrderServer(t, 250, "a")
	db := orderStore(t, "a")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	fake.cancelAt = 6 // the sixth detail cancels the run and never answers
	fake.cancelFn = cancel

	_, err := Orders(ctx, orderReader(t, srv.URL, &orderLimiter{allow: -1}), db, "a")
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
	if _, details := fake.snapshot(); len(details) != 6 {
		t.Fatalf("detail requests = %d, want 6", len(details))
	}
	if n := orderRows(t, db, "a"); n != 5 {
		t.Fatalf("stored = %d, want 5", n)
	}
}

// orderStubReader ignores ctx entirely, so only Orders' own checks can stop it.
type orderStubReader struct {
	calls  int
	cancel context.CancelFunc
	after  int
}

func (s *orderStubReader) Get(_ context.Context, path string, _ url.Values) (json.RawMessage, error) {
	s.calls++
	if s.calls == s.after {
		s.cancel()
	}
	if path == "/pedidos" {
		return json.RawMessage(`{"itens":[{"id":1},{"id":2},{"id":3}],"paginacao":{"limit":100,"offset":0,"total":3}}`), nil
	}
	return json.RawMessage(fmt.Sprintf(`{"id":%s}`, path[len("/pedidos/"):])), nil
}

type orderNopWriter struct{ puts int }

func (w *orderNopWriter) Put(context.Context, store.Record) error { w.puts++; return nil }

func TestOrdersHonorsCancelWhenReaderIgnoresContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	// Call 1 is the list; call 2 is detail 1, which triggers the cancel.
	reader := &orderStubReader{cancel: cancel, after: 2}
	w := &orderNopWriter{}

	_, err := Orders(ctx, reader, w, "a")
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
	if reader.calls != 2 || w.puts != 1 {
		t.Fatalf("reader calls = %d, puts = %d; want 2 and 1 (no fetch or write after cancel)", reader.calls, w.puts)
	}
}

func TestOrdersNeverDeletesExistingRows(t *testing.T) {
	ctx := context.Background()
	_, srv := newOrderServer(t, 2, "a")
	db := orderStore(t, "a")
	// A row the remote listing no longer returns must survive a sync run.
	if err := db.Put(ctx, store.Record{AccountID: "a", Resource: "pedidos", RemoteID: "999", Payload: []byte(`{"id":999}`), ObservedAt: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}

	if _, err := Orders(ctx, orderReader(t, srv.URL, &orderLimiter{allow: -1}), db, "a"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Get(ctx, "a", "pedidos", "999"); err != nil {
		t.Fatalf("existing row removed by sync: %v", err)
	}
	if n := orderRows(t, db, "a"); n != 3 {
		t.Fatalf("stored = %d, want 3 (2 synced plus 1 untouched)", n)
	}
}

func TestOrdersScopedPerAccountAndResource(t *testing.T) {
	ctx := context.Background()
	fakeA, srvA := newOrderServer(t, 250, "a")
	fakeB, srvB := newOrderServer(t, 3, "b")
	db := orderStore(t, "a", "b")
	limA := &orderLimiter{allow: -1}
	limB := &orderLimiter{allow: -1}

	// A product row with the same remote id must not be touched by order sync.
	if err := db.Put(ctx, store.Record{AccountID: "a", Resource: "produtos", RemoteID: "1", Payload: []byte(`{"id":1,"produto":true}`), ObservedAt: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	if _, err := Orders(ctx, orderReader(t, srvA.URL, limA), db, "a"); err != nil {
		t.Fatal(err)
	}
	if _, err := Orders(ctx, orderReader(t, srvB.URL, limB), db, "b"); err != nil {
		t.Fatal(err)
	}

	if n := orderRows(t, db, "a"); n != 250 {
		t.Fatalf("account a orders = %d, want 250", n)
	}
	if n := orderRows(t, db, "b"); n != 3 {
		t.Fatalf("account b orders = %d, want 3", n)
	}
	ra, _ := db.Get(ctx, "a", "pedidos", "1")
	rb, _ := db.Get(ctx, "b", "pedidos", "1")
	if string(ra.Payload) != `{"id":1,"numeroPedido":1,"tag":"a"}` || string(rb.Payload) != `{"id":1,"numeroPedido":1,"tag":"b"}` {
		t.Fatalf("payloads = %s / %s; accounts bled into each other", ra.Payload, rb.Payload)
	}
	prod, err := db.Get(ctx, "a", "produtos", "1")
	if err != nil || string(prod.Payload) != `{"id":1,"produto":true}` {
		t.Fatalf("product row changed by order sync: %s, %v", prod.Payload, err)
	}
	if limA.calls != 3+250 || limB.calls != 1+3 {
		t.Fatalf("limiter calls a=%d b=%d, want 253 and 4", limA.calls, limB.calls)
	}
	if _, details := fakeB.snapshot(); len(details) != 3 {
		t.Fatalf("account b server saw %d details, want 3", len(details))
	}
	if offsets, _ := fakeA.snapshot(); len(offsets) != 3 {
		t.Fatalf("account a list calls = %d, want 3", len(offsets))
	}
}

func TestOrdersRequiresAccountAndDependencies(t *testing.T) {
	ctx := context.Background()
	db := orderStore(t, "a")
	_, srv := newOrderServer(t, 1, "a")
	api := orderReader(t, srv.URL, &orderLimiter{allow: -1})

	if _, err := Orders(ctx, api, db, ""); err == nil {
		t.Error("empty account accepted")
	}
	if _, err := Orders(ctx, nil, db, "a"); err == nil {
		t.Error("nil API accepted")
	}
	if _, err := Orders(ctx, api, nil, "a"); err == nil {
		t.Error("nil store accepted")
	}
}

func TestOrdersUnregisteredAccountFailsAtStore(t *testing.T) {
	fake, srv := newOrderServer(t, 2, "a")
	db := orderStore(t) // no accounts registered

	if _, err := Orders(context.Background(), orderReader(t, srv.URL, &orderLimiter{allow: -1}), db, "ghost"); err == nil {
		t.Fatal("writes for an unregistered account succeeded")
	}
	if _, details := fake.snapshot(); len(details) != 1 {
		t.Fatalf("detail requests = %d, want 1 before the first write fails", len(details))
	}
}

func TestOrderLimiterDenialStopsBeforeNetwork(t *testing.T) {
	fake, srv := newOrderServer(t, 250, "a")
	db := orderStore(t, "a")
	// One list call plus nine details are allowed; the tenth detail is denied.
	lim := &orderLimiter{allow: 10}

	if _, err := Orders(context.Background(), orderReader(t, srv.URL, lim), db, "a"); err == nil || !strings.Contains(err.Error(), "budget exhausted") {
		t.Fatalf("err = %v, want budget exhausted", err)
	}
	offsets, details := fake.snapshot()
	if len(offsets) != 1 || len(details) != 9 || orderRows(t, db, "a") != 9 {
		t.Fatalf("list %v, details %d, stored %d; want 1, 9, 9", offsets, len(details), orderRows(t, db, "a"))
	}
}
