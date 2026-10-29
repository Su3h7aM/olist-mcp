// Package syncer copies Olist data into the local mirror.
package syncer

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"time"

	"github.com/openbot/olist-mcp/internal/store"
)

type Reader interface {
	Get(context.Context, string, url.Values) (json.RawMessage, error)
}
type Writer interface {
	Put(context.Context, store.Record) error
}
type Progress struct {
	Pages   int
	Records int
}

// Products copies product detail records for one account. An interrupted run can
// safely be restarted; completion does not imply deletion reconciliation.
func Products(ctx context.Context, api Reader, db Writer, account string) (Progress, error) {
	var progress Progress
	if account == "" || api == nil || db == nil {
		return progress, errors.New("account, API and store are required")
	}
	const limit = 100
	for offset := 0; ; offset += limit {
		raw, err := api.Get(ctx, "/produtos", url.Values{"limit": {"100"}, "offset": {strconv.Itoa(offset)}})
		if err != nil {
			return progress, err
		}
		var page struct {
			Items      []json.RawMessage `json:"itens"`
			Pagination *struct {
				Limit  int `json:"limit"`
				Offset int `json:"offset"`
				Total  int `json:"total"`
			} `json:"paginacao"`
		}
		if err = json.Unmarshal(raw, &page); err != nil || page.Pagination == nil || page.Items == nil {
			return progress, errors.New("invalid product list response")
		}
		p := page.Pagination
		if p.Offset != offset || p.Limit <= 0 || p.Total < 0 || len(page.Items) > limit || (len(page.Items) == 0 && offset < p.Total) {
			return progress, errors.New("invalid product pagination")
		}
		for _, item := range page.Items {
			var v struct {
				ID json.Number `json:"id"`
			}
			if err = json.Unmarshal(item, &v); err != nil {
				return progress, errors.New("invalid product ID")
			}
			id, err := strconv.ParseInt(v.ID.String(), 10, 64)
			if err != nil || id <= 0 {
				return progress, errors.New("invalid product ID")
			}
			detail, err := api.Get(ctx, fmt.Sprintf("/produtos/%d", id), nil)
			if err != nil {
				return progress, err
			}
			if err = db.Put(ctx, store.Record{AccountID: account, Resource: "produtos", RemoteID: strconv.FormatInt(id, 10), Payload: detail, ObservedAt: time.Now().UTC()}); err != nil {
				return progress, err
			}
			progress.Records++
		}
		progress.Pages++
		next := offset + len(page.Items)
		if next >= p.Total {
			return progress, nil
		}
		if len(page.Items) != limit {
			return progress, errors.New("incomplete product page")
		}
	}
}
