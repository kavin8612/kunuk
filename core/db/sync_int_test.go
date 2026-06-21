package db_test

// Test d'integrazione HTTP del modulo sync (delta CRDT, task 1.2): cursore monotono
// (sync_change.id), happy path push+pull e i test IDOR obbligatori (SR-30): il token di A non
// legge né scrive i delta del vault di B.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"kunuk.dev/core/internal/config"
	"kunuk.dev/core/internal/httpserver"
	"kunuk.dev/core/internal/session"
)

func pushChangesBody(ciphertexts ...[]byte) string {
	changes := make([]string, len(ciphertexts))
	for i, ct := range ciphertexts {
		changes[i] = fmt.Sprintf(`{"ciphertext":%q,"clock":"c%d"}`, b64(ct), i)
	}
	return fmt.Sprintf(`{"changes":[%s]}`, strings.Join(changes, ","))
}

type syncPage struct {
	Items []struct {
		ID         string  `json:"id"`
		DeviceID   *string `json:"device_id"`
		Ciphertext string  `json:"ciphertext"`
		Clock      string  `json:"clock"`
	} `json:"items"`
	NextCursor *string `json:"next_cursor"`
}

// listChanges richiede una pagina. `cursor` è il token OPACO (già base64url) restituito da
// `next_cursor`: il chiamante non lo decodifica né lo ricostruisce mai a mano (doc 21).
func listChanges(t *testing.T, router http.Handler, token, cursor string) syncPage {
	t.Helper()
	return listChangesWithLimit(t, router, token, cursor, 0)
}

func listChangesWithLimit(t *testing.T, router http.Handler, token, cursor string, limit int) syncPage {
	t.Helper()
	path := "/v1/sync/changes"
	q := url.Values{}
	if cursor != "" {
		q.Set("cursor", cursor)
	}
	if limit > 0 {
		q.Set("limit", strconv.Itoa(limit))
	}
	if enc := q.Encode(); enc != "" {
		path += "?" + enc
	}
	w := reqWithToken(t, router, http.MethodGet, path, token)
	assertStatus(t, w, http.StatusOK)
	var page syncPage
	if err := json.Unmarshal(w.Body.Bytes(), &page); err != nil {
		t.Fatalf("decode sync page: %v", err)
	}
	return page
}

func TestSyncPushPullHappyPath(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	pool, _ := setupPreauth(ctx, t)
	idA := mustRegister(ctx, t, pool, "a@example.com")
	sessions := session.NewService(pool, time.Hour)
	tokA := mustIssue(t, ctx, sessions, idA)
	router := httpserver.NewRouter(httpserver.Deps{Pool: pool, Sessions: sessions, Config: config.Config{}})

	// Nessun delta all'inizio.
	page := listChanges(t, router, tokA, "")
	if len(page.Items) != 0 {
		t.Fatalf("attesi 0 delta, ottenuti %d", len(page.Items))
	}

	// Push di due delta cifrati (ciphertext opachi: il server non li legge).
	w := reqJSON(t, router, http.MethodPost, "/v1/sync/changes", tokA,
		pushChangesBody([]byte{0x01, 0x02}, []byte{0x03, 0x04}))
	assertStatus(t, w, http.StatusAccepted)

	page = listChanges(t, router, tokA, "")
	if len(page.Items) != 2 {
		t.Fatalf("attesi 2 delta, ottenuti %d", len(page.Items))
	}
	if page.Items[0].Ciphertext != b64([]byte{0x01, 0x02}) || page.Items[1].Ciphertext != b64([]byte{0x03, 0x04}) {
		t.Fatalf("ciphertext non byte-identici: %+v", page.Items)
	}
	if page.Items[0].DeviceID != nil {
		t.Fatalf("device_id deve restare nil (nessun modulo devices nel task 1.2)")
	}

	// Pagina con limite 1: forza un next_cursor, MAI ricostruito a mano (è opaco, doc 21).
	first := listChangesWithLimit(t, router, tokA, "", 1)
	if len(first.Items) != 1 || first.NextCursor == nil {
		t.Fatalf("con limit=1 attesi 1 delta e un next_cursor: %+v", first)
	}
	if first.Items[0].ID != page.Items[0].ID {
		t.Fatalf("prima pagina inattesa: %+v", first.Items)
	}
	rest := listChanges(t, router, tokA, *first.NextCursor)
	if len(rest.Items) != 1 || rest.Items[0].ID != page.Items[1].ID {
		t.Fatalf("seconda pagina: attesi solo il secondo delta, ottenuti %+v", rest.Items)
	}
}

func TestSyncCursorPaginazione(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	pool, _ := setupPreauth(ctx, t)
	idA := mustRegister(ctx, t, pool, "a@example.com")
	sessions := session.NewService(pool, time.Hour)
	tokA := mustIssue(t, ctx, sessions, idA)
	router := httpserver.NewRouter(httpserver.Deps{Pool: pool, Sessions: sessions, Config: config.Config{}})

	assertStatus(t, reqJSON(t, router, http.MethodPost, "/v1/sync/changes", tokA,
		pushChangesBody([]byte{1}, []byte{2}, []byte{3})), http.StatusAccepted)

	first := listChanges(t, router, tokA, "")
	if len(first.Items) != 3 || first.NextCursor != nil {
		t.Fatalf("con limite di default attesi i 3 delta in una pagina, next_cursor nil: %+v", first)
	}
}

func TestSyncIDOR(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	pool, _ := setupPreauth(ctx, t)
	idA := mustRegister(ctx, t, pool, "a@example.com")
	idB := mustRegister(ctx, t, pool, "b@example.com")
	sessions := session.NewService(pool, time.Hour)
	tokA := mustIssue(t, ctx, sessions, idA)
	tokB := mustIssue(t, ctx, sessions, idB)
	router := httpserver.NewRouter(httpserver.Deps{Pool: pool, Sessions: sessions, Config: config.Config{}})

	// B pusha un delta; A non deve vederlo nella propria pull (RLS sul vault di B).
	assertStatus(t, reqJSON(t, router, http.MethodPost, "/v1/sync/changes", tokB,
		pushChangesBody([]byte{0xB1})), http.StatusAccepted)

	pageA := listChanges(t, router, tokA, "")
	if len(pageA.Items) != 0 {
		t.Fatalf("A non deve vedere i delta del vault di B: %+v", pageA.Items)
	}
	pageB := listChanges(t, router, tokB, "")
	if len(pageB.Items) != 1 {
		t.Fatalf("B deve vedere il proprio delta: %+v", pageB.Items)
	}
}
