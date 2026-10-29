package olist

import (
	"context"
	"encoding/json"
	"errors"
	"net/url"
)

// ReadLimiter must be shared by every client serving the same Olist account.
type ReadLimiter interface {
	Wait(context.Context, bool) error
}

// LimitedReader makes every API call consume the account's read budget.
type LimitedReader struct {
	client   *Client
	limiter  ReadLimiter
	onDemand bool
}

func NewLimitedReader(client *Client, limiter ReadLimiter, onDemand bool) (*LimitedReader, error) {
	if client == nil || limiter == nil {
		return nil, errors.New("client and account limiter are required")
	}
	return &LimitedReader{client, limiter, onDemand}, nil
}
func (r *LimitedReader) Get(ctx context.Context, path string, query url.Values) (json.RawMessage, error) {
	if err := r.limiter.Wait(ctx, r.onDemand); err != nil {
		return nil, err
	}
	return r.client.Get(ctx, path, query)
}
