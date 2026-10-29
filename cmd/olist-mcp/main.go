// Command olist-mcp currently serves a local-only diagnostic prototype.
// It does not provide authentication or access to ERP data.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/openbot/olist-mcp/internal/mcpserver"
)

func run(ctx context.Context, address string) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("invalid listen address: %w", err)
	}
	ip := net.ParseIP(host)
	if host != "localhost" && (ip == nil || !ip.IsLoopback()) {
		return errors.New("prototype requires a loopback listen address")
	}
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return err
	}
	mux := http.NewServeMux()
	mux.Handle("/mcp", mcpserver.Handler())
	server := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	done := make(chan error, 1)
	go func() { done <- server.Serve(listener) }()
	log.Printf("local diagnostic prototype listening at http://%s/mcp", listener.Addr())
	select {
	case <-ctx.Done():
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdown); err != nil {
			return err
		}
		err = <-done
	case err = <-done:
	}
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}
func main() {
	address := flag.String("listen", "127.0.0.1:8080", "loopback address for diagnostic prototype")
	flag.Parse()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, *address); err != nil {
		log.Fatal(err)
	}
}
