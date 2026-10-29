package olist

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

type deniedLimiter struct{}

func (deniedLimiter) Wait(context.Context, bool) error { return errors.New("budget exhausted") }
func TestLimitedReaderStopsBeforeNetwork(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Error("request should not be sent") }))
	defer server.Close()
	client, err := NewClient(server.URL, func(context.Context) (string, error) { return "token", nil })
	if err != nil {
		t.Fatal(err)
	}
	reader, err := NewLimitedReader(client, deniedLimiter{}, false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = reader.Get(context.Background(), "/produtos", nil); err == nil {
		t.Fatal("missing limit error")
	}
}
