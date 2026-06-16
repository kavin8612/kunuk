package httpx

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestLimit(t *testing.T) {
	cases := map[string]int{"": 50, "10": 10, "9999": 200, "0": 50, "abc": 50}
	for q, want := range cases {
		r := httptest.NewRequest(http.MethodGet, "/v1/items?limit="+q, nil)
		if got := Limit(r); got != want {
			t.Errorf("Limit(limit=%q) = %d, atteso %d", q, got, want)
		}
	}
}

func TestCursorRoundTrip(t *testing.T) {
	enc := EncodeCursor("updated_at|id")
	r := httptest.NewRequest(http.MethodGet, "/v1/items?cursor="+enc, nil)
	got, err := Cursor(r)
	if err != nil {
		t.Fatalf("Cursor: %v", err)
	}
	if got != "updated_at|id" {
		t.Fatalf("cursore = %q, atteso il token originale", got)
	}
}

func TestCursorMalformato(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/v1/items?cursor=!!!non-base64!!!", nil)
	if _, err := Cursor(r); err == nil {
		t.Fatal("Cursor doveva fallire su input non base64url")
	}
}

func TestNewPageNullCursor(t *testing.T) {
	p := NewPage([]int{1, 2}, "")
	if p.NextCursor != nil {
		t.Fatalf("next_cursor doveva essere nil senza altre pagine")
	}
	b, err := json.Marshal(p)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if string(b) != `{"items":[1,2],"next_cursor":null}` {
		t.Fatalf("JSON inatteso: %s", b)
	}
}

func TestNewPageEmptyItems(t *testing.T) {
	p := NewPage[int](nil, "tok")
	if p.NextCursor == nil || *p.NextCursor == "" {
		t.Fatal("next_cursor doveva essere valorizzato")
	}
	b, err := json.Marshal(p)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !strings.HasPrefix(string(b), `{"items":[]`) {
		t.Fatalf("items doveva essere [] non null: %s", b)
	}
}
