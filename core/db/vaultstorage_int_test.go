package db_test

// Test d'integrazione HTTP del modulo vault-storage: buste, manifest (con CAS di versione →
// 409) e item CRUD. Soprattutto i test IDOR obbligatori (SR-30): il token di A non legge né
// scrive vault/item di B (la RLS li nasconde → 404), end-to-end via HTTP.

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"kunuk.dev/core/internal/config"
	"kunuk.dev/core/internal/httpserver"
	"kunuk.dev/core/internal/session"
)

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func itemBody(ct, cek []byte) string {
	return fmt.Sprintf(`{"ciphertext":%q,"wrapped_cek":%q}`, b64(ct), b64(cek))
}

func itemBodyWithID(id string, ct, cek []byte) string {
	return fmt.Sprintf(`{"id":%q,"ciphertext":%q,"wrapped_cek":%q}`, id, b64(ct), b64(cek))
}

func manifestBody(manifest, sig []byte, version int) string {
	return fmt.Sprintf(`{"manifest":%q,"signature":%q,"version":%d}`, b64(manifest), b64(sig), version)
}

func reqJSON(t *testing.T, router http.Handler, method, path, token, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	return w
}

func mustIssue(t *testing.T, ctx context.Context, sessions *session.Service, accountID string) string {
	t.Helper()
	tok, _, err := sessions.Issue(ctx, accountID)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	return tok
}

func createItem(t *testing.T, router http.Handler, token string) string {
	t.Helper()
	w := reqJSON(t, router, http.MethodPost, "/v1/items", token, itemBody([]byte{1, 2, 3}, []byte{4, 5, 6}))
	assertStatus(t, w, http.StatusCreated)
	var got struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode item: %v", err)
	}
	return got.ID
}

func assertItemNotListed(t *testing.T, router http.Handler, token, notID string) {
	t.Helper()
	w := reqWithToken(t, router, http.MethodGet, "/v1/items", token)
	assertStatus(t, w, http.StatusOK)
	var page struct {
		Items []struct {
			ID string `json:"id"`
		} `json:"items"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &page); err != nil {
		t.Fatalf("decode page: %v", err)
	}
	for _, it := range page.Items {
		if it.ID == notID {
			t.Fatal("A non deve vedere l'item di B nella lista")
		}
	}
}

func TestVaultStorageHappyPath(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	pool, _ := setupPreauth(ctx, t)
	idA := mustRegister(ctx, t, pool, "a@example.com")
	sessions := session.NewService(pool, time.Hour)
	tokA := mustIssue(t, ctx, sessions, idA)
	router := httpserver.NewRouter(httpserver.Deps{Pool: pool, Sessions: sessions, Config: config.Config{}})

	dummy := []byte{0xAA, 0xBB}
	// Vault: A legge il proprio manifest (versione 1 dalla registrazione).
	assertStatus(t, reqWithToken(t, router, http.MethodGet, "/v1/vault", tokA), http.StatusOK)
	// CAS versione: 2 accettata, 1 (rollback) → 409.
	assertStatus(t, reqJSON(t, router, http.MethodPut, "/v1/vault/manifest", tokA, manifestBody(dummy, dummy, 2)), http.StatusOK)
	assertStatus(t, reqJSON(t, router, http.MethodPut, "/v1/vault/manifest", tokA, manifestBody(dummy, dummy, 1)), http.StatusConflict)
	// Buste.
	assertStatus(t, reqWithToken(t, router, http.MethodGet, "/v1/envelopes", tokA), http.StatusOK)
	// Item CRUD.
	id := createItem(t, router, tokA)
	assertStatus(t, reqWithToken(t, router, http.MethodGet, "/v1/items", tokA), http.StatusOK)
	assertStatus(t, reqWithToken(t, router, http.MethodGet, "/v1/items/"+id, tokA), http.StatusOK)
	assertStatus(t, reqJSON(t, router, http.MethodPut, "/v1/items/"+id, tokA, itemBody(dummy, dummy)), http.StatusOK)
	assertStatus(t, reqWithToken(t, router, http.MethodDelete, "/v1/items/"+id, tokA), http.StatusNoContent)
}

// TestGetVaultExposesWrappedSigningKey copre il gap analogo a quello di account_id/vault_id
// (ADR-0020): senza wrapped_signing_key in GET /vault, nessun client che non sia la sessione
// di registrazione potrebbe ri-firmare un nuovo manifest (es. dopo un login, o un CRUD item,
// task 1.3/C2). Il valore deve tornare byte-identico a quello inviato alla registrazione.
func TestGetVaultExposesWrappedSigningKey(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	pool, _ := setupPreauth(ctx, t)
	idA := mustRegister(ctx, t, pool, "a@example.com")
	sessions := session.NewService(pool, time.Hour)
	tokA := mustIssue(t, ctx, sessions, idA)
	router := httpserver.NewRouter(httpserver.Deps{Pool: pool, Sessions: sessions, Config: config.Config{}})

	w := reqWithToken(t, router, http.MethodGet, "/v1/vault", tokA)
	assertStatus(t, w, http.StatusOK)
	var got struct {
		WrappedSigningKey string `json:"wrapped_signing_key"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode vault: %v", err)
	}
	// sampleRegister (preauth_int_test.go) usa lo stesso dummy {0x01,0x02,0x03} per
	// wrapped_signing_key alla registrazione.
	want := b64([]byte{0x01, 0x02, 0x03})
	if got.WrappedSigningKey != want {
		t.Fatalf("wrapped_signing_key: atteso %q, ottenuto %q", want, got.WrappedSigningKey)
	}
}

// TestCreateItemWithClientID copre l'id scelto dal client (necessario per il binding AAD
// vault_id‖item_id, doc 16 §5; usato dalla CLI del gate 0.10): l'id torna invariato nella
// risposta, un id duplicato dà 409 e un id malformato 400.
func TestCreateItemWithClientID(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	pool, _ := setupPreauth(ctx, t)
	idA := mustRegister(ctx, t, pool, "a@example.com")
	sessions := session.NewService(pool, time.Hour)
	tokA := mustIssue(t, ctx, sessions, idA)
	router := httpserver.NewRouter(httpserver.Deps{Pool: pool, Sessions: sessions, Config: config.Config{}})

	const clientID = "11111111-2222-3333-4444-555555555555"
	ct, cek := []byte{0xDE, 0xAD}, []byte{0xBE, 0xEF}

	// L'id fornito dal client viene usato tale e quale.
	w := reqJSON(t, router, http.MethodPost, "/v1/items", tokA, itemBodyWithID(clientID, ct, cek))
	assertStatus(t, w, http.StatusCreated)
	var got struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode item: %v", err)
	}
	if got.ID != clientID {
		t.Fatalf("id non rispettato: atteso %s, ottenuto %s", clientID, got.ID)
	}
	// Rilettura per quell'id: presente e byte-identico.
	assertStatus(t, reqWithToken(t, router, http.MethodGet, "/v1/items/"+clientID, tokA), http.StatusOK)
	// Id duplicato → 409 (non un 500 opaco).
	assertStatus(t, reqJSON(t, router, http.MethodPost, "/v1/items", tokA, itemBodyWithID(clientID, ct, cek)), http.StatusConflict)
	// Id malformato → 400.
	assertStatus(t, reqJSON(t, router, http.MethodPost, "/v1/items", tokA, itemBodyWithID("non-un-uuid", ct, cek)), http.StatusBadRequest)
}

func TestVaultStorageIDOR(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	pool, _ := setupPreauth(ctx, t)
	idA := mustRegister(ctx, t, pool, "a@example.com")
	idB := mustRegister(ctx, t, pool, "b@example.com")
	sessions := session.NewService(pool, time.Hour)
	tokA := mustIssue(t, ctx, sessions, idA)
	tokB := mustIssue(t, ctx, sessions, idB)
	router := httpserver.NewRouter(httpserver.Deps{Pool: pool, Sessions: sessions, Config: config.Config{}})

	// B crea un item; A non deve poterlo leggere né scrivere (RLS → 404).
	itemB := createItem(t, router, tokB)
	dummy := []byte{0x01}
	assertStatus(t, reqWithToken(t, router, http.MethodGet, "/v1/items/"+itemB, tokA), http.StatusNotFound)
	assertStatus(t, reqJSON(t, router, http.MethodPut, "/v1/items/"+itemB, tokA, itemBody(dummy, dummy)), http.StatusNotFound)
	assertStatus(t, reqWithToken(t, router, http.MethodDelete, "/v1/items/"+itemB, tokA), http.StatusNotFound)
	// L'item di B non compare nella lista di A.
	assertItemNotListed(t, router, tokA, itemB)
}

// TestCreateItemSameIDDifferentAccounts è il test di regressione dell'oracolo cross-tenant
// (hardening 0.10, migrazione 00003): lo stesso item id scelto da due account diversi NON
// deve dare conflitto (la chiave è composita (vault_id, id), unica per-vault). Prima del fix
// l'id era PK globale → il secondo POST otteneva 409, confermando l'esistenza dell'item
// dell'altro tenant anche sotto RLS (in tensione con SR-26).
func TestCreateItemSameIDDifferentAccounts(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	pool, _ := setupPreauth(ctx, t)
	idA := mustRegister(ctx, t, pool, "a@example.com")
	idB := mustRegister(ctx, t, pool, "b@example.com")
	sessions := session.NewService(pool, time.Hour)
	tokA := mustIssue(t, ctx, sessions, idA)
	tokB := mustIssue(t, ctx, sessions, idB)
	router := httpserver.NewRouter(httpserver.Deps{Pool: pool, Sessions: sessions, Config: config.Config{}})

	const sharedID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
	ctA, cekA := []byte{0xA1}, []byte{0xA2}
	ctB, cekB := []byte{0xB1}, []byte{0xB2}

	// A e B creano un item con lo STESSO id: entrambi 201, nessun oracolo cross-tenant.
	assertStatus(t, reqJSON(t, router, http.MethodPost, "/v1/items", tokA, itemBodyWithID(sharedID, ctA, cekA)), http.StatusCreated)
	assertStatus(t, reqJSON(t, router, http.MethodPost, "/v1/items", tokB, itemBodyWithID(sharedID, ctB, cekB)), http.StatusCreated)

	// Ciascuno rilegge il PROPRIO item per quell'id (RLS scoping), byte-identico.
	wA := reqWithToken(t, router, http.MethodGet, "/v1/items/"+sharedID, tokA)
	assertStatus(t, wA, http.StatusOK)
	if !strings.Contains(wA.Body.String(), b64(ctA)) {
		t.Fatalf("A deve rileggere il proprio ciphertext, non quello di B: %s", wA.Body.String())
	}
	// Per A un duplicato nel PROPRIO vault resta un conflitto legittimo (409).
	assertStatus(t, reqJSON(t, router, http.MethodPost, "/v1/items", tokA, itemBodyWithID(sharedID, ctA, cekA)), http.StatusConflict)
}
