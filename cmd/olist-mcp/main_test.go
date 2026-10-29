package main

import (
	"context"
	"strings"
	"testing"
)

func TestRejectNonLoopback(t *testing.T) {
	for _, addr := range []string{"0.0.0.0:8080", ":8080", "example.com:8080"} {
		if err := run(context.Background(), addr); err == nil || !strings.Contains(err.Error(), "loopback") {
			t.Fatalf("%s: %v", addr, err)
		}
	}
}
