package store

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func coverageStore(t *testing.T, accounts ...string) (*Store, string) {
	t.Helper()
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "mirror.db")
	s, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	for _, a := range accounts {
		if err := s.PutAccount(ctx, a, a); err != nil {
			t.Fatal(err)
		}
	}
	return s, path
}

func covTime(day int) time.Time {
	return time.Date(2026, 10, day, 8, 30, 0, 123456789, time.UTC)
}

func TestCoverageRoundTripCompleteWithCursor(t *testing.T) {
	ctx := context.Background()
	s, _ := coverageStore(t, "a")
	want := Coverage{AccountID: "a", Resource: "produtos", SyncClass: "list", Status: StatusComplete,
		LastSuccessAt: covTime(1), Cursor: "offset:250"}
	if err := s.UpsertCoverage(ctx, want); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetCoverage(ctx, "a", "produtos")
	if err != nil {
		t.Fatal(err)
	}
	if got.SyncClass != "list" || got.Status != StatusComplete || got.Cursor != "offset:250" {
		t.Fatalf("coverage = %+v", got)
	}
	if !got.LastSuccessAt.Equal(covTime(1)) {
		t.Fatalf("last success = %v, want %v", got.LastSuccessAt, covTime(1))
	}
}

func TestCoverageNoCursorAndNeverSyncedAreNull(t *testing.T) {
	ctx := context.Background()
	s, _ := coverageStore(t, "a")
	if err := s.UpsertCoverage(ctx, Coverage{AccountID: "a", Resource: "contatos", SyncClass: "list", Status: StatusPending}); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetCoverage(ctx, "a", "contatos")
	if err != nil {
		t.Fatal(err)
	}
	if !got.LastSuccessAt.IsZero() || got.Cursor != "" {
		t.Fatalf("empty optional fields not preserved as empty: %+v", got)
	}
}

func TestCoverageAccountIsolation(t *testing.T) {
	ctx := context.Background()
	s, _ := coverageStore(t, "a", "b")
	if err := s.UpsertCoverage(ctx, Coverage{AccountID: "a", Resource: "produtos", SyncClass: "list", Status: StatusComplete, LastSuccessAt: covTime(1)}); err != nil {
		t.Fatal(err)
	}
	if err := s.UpsertCoverage(ctx, Coverage{AccountID: "b", Resource: "produtos", SyncClass: "list", Status: StatusError}); err != nil {
		t.Fatal(err)
	}
	a, err := s.GetCoverage(ctx, "a", "produtos")
	if err != nil || a.Status != StatusComplete {
		t.Fatalf("account a: %+v, %v", a, err)
	}
	b, err := s.GetCoverage(ctx, "b", "produtos")
	if err != nil || b.Status != StatusError || !b.LastSuccessAt.IsZero() {
		t.Fatalf("account b changed by account a's row: %+v, %v", b, err)
	}
	if _, err := s.GetCoverage(ctx, "a", "contatos"); !errors.Is(err, ErrNoCoverage) {
		t.Fatalf("other resource found: %v", err)
	}
}

func TestPartialAndErrorRunsNeverAdvanceLastSuccess(t *testing.T) {
	ctx := context.Background()
	s, _ := coverageStore(t, "a")
	if err := s.UpsertCoverage(ctx, Coverage{AccountID: "a", Resource: "pedidos", SyncClass: "list", Status: StatusComplete, LastSuccessAt: covTime(1)}); err != nil {
		t.Fatal(err)
	}
	// A later partial run may pass a newer time, but it must not be stored.
	if err := s.UpsertCoverage(ctx, Coverage{AccountID: "a", Resource: "pedidos", SyncClass: "list", Status: StatusPartial, LastSuccessAt: covTime(5), Cursor: "offset:100"}); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetCoverage(ctx, "a", "pedidos")
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != StatusPartial || got.Cursor != "offset:100" {
		t.Fatalf("partial status/cursor not stored: %+v", got)
	}
	if !got.LastSuccessAt.Equal(covTime(1)) {
		t.Fatalf("partial run advanced last success to %v", got.LastSuccessAt)
	}
	if err := s.UpsertCoverage(ctx, Coverage{AccountID: "a", Resource: "pedidos", SyncClass: "list", Status: StatusError}); err != nil {
		t.Fatal(err)
	}
	got, _ = s.GetCoverage(ctx, "a", "pedidos")
	if got.Status != StatusError || !got.LastSuccessAt.Equal(covTime(1)) {
		t.Fatalf("error run changed last success: %+v", got)
	}
}

func TestPartialRunOnNewRowHasNoLastSuccess(t *testing.T) {
	ctx := context.Background()
	s, _ := coverageStore(t, "a")
	if err := s.UpsertCoverage(ctx, Coverage{AccountID: "a", Resource: "produtos", SyncClass: "list", Status: StatusPartial, LastSuccessAt: covTime(3)}); err != nil {
		t.Fatal(err)
	}
	got, _ := s.GetCoverage(ctx, "a", "produtos")
	if !got.LastSuccessAt.IsZero() {
		t.Fatalf("partial run on a new row recorded success at %v", got.LastSuccessAt)
	}
}

func TestCompleteRequiresLastSuccessTime(t *testing.T) {
	ctx := context.Background()
	s, _ := coverageStore(t, "a")
	err := s.UpsertCoverage(ctx, Coverage{AccountID: "a", Resource: "produtos", SyncClass: "list", Status: StatusComplete})
	if err == nil {
		t.Fatal("complete coverage without a success time was stored")
	}
	if _, err := s.GetCoverage(ctx, "a", "produtos"); !errors.Is(err, ErrNoCoverage) {
		t.Fatalf("rejected write left a row: %v", err)
	}
}

func TestCoverageUpdateAndReopenPersists(t *testing.T) {
	ctx := context.Background()
	s, path := coverageStore(t, "a")
	if err := s.UpsertCoverage(ctx, Coverage{AccountID: "a", Resource: "produtos", SyncClass: "list", Status: StatusPending}); err != nil {
		t.Fatal(err)
	}
	if err := s.UpsertCoverage(ctx, Coverage{AccountID: "a", Resource: "produtos", SyncClass: "list", Status: StatusComplete, LastSuccessAt: covTime(2), Cursor: ""}); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	got, err := reopened.GetCoverage(ctx, "a", "produtos")
	if err != nil {
		t.Fatalf("coverage lost on reopen: %v", err)
	}
	if got.Status != StatusComplete || !got.LastSuccessAt.Equal(covTime(2)) {
		t.Fatalf("after reopen: %+v", got)
	}
	if err := reopened.UpsertCoverage(ctx, Coverage{AccountID: "a", Resource: "produtos", SyncClass: "list", Status: StatusPartial, Cursor: "offset:50"}); err != nil {
		t.Fatal(err)
	}
	got, _ = reopened.GetCoverage(ctx, "a", "produtos")
	if got.Status != StatusPartial || !got.LastSuccessAt.Equal(covTime(2)) {
		t.Fatalf("update after reopen lost previous success: %+v", got)
	}
}

func TestInvalidStatusRejected(t *testing.T) {
	ctx := context.Background()
	s, _ := coverageStore(t, "a")
	for _, status := range []Status{"", "done", "COMPLETE", "failed", " partial"} {
		err := s.UpsertCoverage(ctx, Coverage{AccountID: "a", Resource: "produtos", SyncClass: "list", Status: status, LastSuccessAt: covTime(1)})
		if err == nil {
			t.Fatalf("status %q accepted", status)
		}
	}
	if _, err := s.GetCoverage(ctx, "a", "produtos"); !errors.Is(err, ErrNoCoverage) {
		t.Fatalf("invalid status left a row: %v", err)
	}
}

// The CHECK constraint must also reject invalid statuses written outside the typed API.
func TestDatabaseRejectsInvalidStatusDirectly(t *testing.T) {
	ctx := context.Background()
	s, _ := coverageStore(t, "a")
	_, err := s.db.ExecContext(ctx, `INSERT INTO sync_coverage(account_id,resource,sync_class,status) VALUES('a','produtos','list','done')`)
	if err == nil {
		t.Fatal("schema accepted an invalid status")
	}
}

func TestMissingAccountRejected(t *testing.T) {
	ctx := context.Background()
	s, _ := coverageStore(t, "a")
	err := s.UpsertCoverage(ctx, Coverage{AccountID: "ghost", Resource: "produtos", SyncClass: "list", Status: StatusPending})
	if err == nil {
		t.Fatal("coverage for an unknown account stored")
	}
	if _, err := s.GetCoverage(ctx, "ghost", "produtos"); !errors.Is(err, ErrNoCoverage) {
		t.Fatalf("unknown account has coverage: %v", err)
	}
}

func TestRequiredFieldsRejected(t *testing.T) {
	ctx := context.Background()
	s, _ := coverageStore(t, "a")
	cases := map[string]Coverage{
		"empty account":  {Resource: "produtos", SyncClass: "list", Status: StatusPending},
		"blank resource": {AccountID: "a", Resource: "  ", SyncClass: "list", Status: StatusPending},
		"empty class":    {AccountID: "a", Resource: "produtos", Status: StatusPending},
	}
	for name, c := range cases {
		if err := s.UpsertCoverage(ctx, c); err == nil {
			t.Fatalf("%s accepted", name)
		}
	}
}

func TestGetCoverageRequiresKeys(t *testing.T) {
	ctx := context.Background()
	s, _ := coverageStore(t, "a")
	if _, err := s.GetCoverage(ctx, "", "produtos"); err == nil {
		t.Fatal("empty account accepted for read")
	}
	if _, err := s.GetCoverage(ctx, "a", ""); err == nil {
		t.Fatal("empty resource accepted for read")
	}
}

func TestCompleteClearsNothingElseAndKeepsCursorWhenGiven(t *testing.T) {
	ctx := context.Background()
	s, _ := coverageStore(t, "a")
	if err := s.UpsertCoverage(ctx, Coverage{AccountID: "a", Resource: "produtos", SyncClass: "list", Status: StatusComplete, LastSuccessAt: covTime(4), Cursor: "last"}); err != nil {
		t.Fatal(err)
	}
	got, _ := s.GetCoverage(ctx, "a", "produtos")
	if got.Cursor != "last" || !got.LastSuccessAt.Equal(covTime(4)) {
		t.Fatalf("complete row = %+v", got)
	}
}
