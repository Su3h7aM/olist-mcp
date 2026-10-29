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

// Contacts copies contact detail records (GET /contatos/{idContato}) for one
// account, paging through GET /contatos. Records are upserted per account; the
// run never deletes local rows. An interrupted run can be restarted safely.
// Contacts with situacao "E" (excluded) are stored as returned by Olist.
func Contacts(ctx context.Context, api Reader, db Writer, account string) (Progress, error) {
	var progress Progress
	if account == "" || api == nil || db == nil {
		return progress, errors.New("account, API and store are required")
	}
	const limit = 100
	for offset := 0; ; offset += limit {
		if err := ctx.Err(); err != nil {
			return progress, err
		}
		raw, err := api.Get(ctx, "/contatos", url.Values{"limit": {strconv.Itoa(limit)}, "offset": {strconv.Itoa(offset)}})
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
			return progress, errors.New("invalid contact list response")
		}
		p := page.Pagination
		if p.Offset != offset || p.Limit != limit || p.Total < offset || len(page.Items) > limit || len(page.Items) > p.Total-offset || (len(page.Items) < limit && offset+len(page.Items) < p.Total) {
			return progress, errors.New("invalid contact pagination")
		}
		// Validate every list item before fetching any detail or writing any row.
		ids := make([]int64, 0, len(page.Items))
		for _, item := range page.Items {
			id, err := contactID(item)
			if err != nil {
				return progress, err
			}
			ids = append(ids, id)
		}
		for _, id := range ids {
			if err := ctx.Err(); err != nil {
				return progress, err
			}
			detail, err := api.Get(ctx, fmt.Sprintf("/contatos/%d", id), nil)
			if err != nil {
				return progress, err
			}
			detailID, err := contactID(detail)
			if err != nil || detailID != id {
				return progress, errors.New("contact detail ID mismatch or missing")
			}
			if err = db.Put(ctx, store.Record{AccountID: account, Resource: "contatos", RemoteID: strconv.FormatInt(id, 10), Payload: detail, ObservedAt: time.Now().UTC()}); err != nil {
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
			return progress, errors.New("incomplete contact page")
		}
	}
}

// contactID extracts a positive integer "id" from a contact JSON object.
// The OpenAPI schema types id as integer, so quoted numbers are rejected.
func contactID(raw json.RawMessage) (int64, error) {
	var v struct {
		ID json.RawMessage `json:"id"`
	}
	if err := json.Unmarshal(raw, &v); err != nil {
		return 0, errors.New("invalid contact ID")
	}
	if len(v.ID) == 0 || v.ID[0] == '"' {
		return 0, errors.New("invalid contact ID")
	}
	id, err := strconv.ParseInt(string(v.ID), 10, 64)
	if err != nil || id <= 0 {
		return 0, errors.New("invalid contact ID")
	}
	return id, nil
}
