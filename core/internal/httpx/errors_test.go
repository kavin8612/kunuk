package httpx

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"kunuk.dev/core/internal/reqctx"
)

func TestStatus(t *testing.T) {
	cases := map[ErrorCode]int{
		CodeInvalidRequest:  400,
		CodeUnauthorized:    401,
		CodeNotFound:        404,
		CodeConflict:        409,
		CodeTooEarly:        425,
		CodeRateLimited:     429,
		CodeInternal:        500,
		ErrorCode("ignoto"): 500,
	}
	for code, want := range cases {
		if got := Status(code); got != want {
			t.Errorf("Status(%q) = %d, atteso %d", code, got, want)
		}
	}
}

func TestWriteError(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/v1/account", nil)
	r = r.WithContext(reqctx.WithRequestID(r.Context(), "req-123"))
	w := httptest.NewRecorder()

	WriteError(w, r, CodeInvalidRequest, "campo mancante")

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, atteso 400", w.Code)
	}
	var env struct {
		Error struct {
			Code      string `json:"code"`
			Message   string `json:"message"`
			RequestID string `json:"request_id"`
		} `json:"error"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &env); err != nil {
		t.Fatalf("corpo non JSON: %v", err)
	}
	if env.Error.Code != "invalid_request" || env.Error.RequestID != "req-123" {
		t.Fatalf("envelope inatteso: %+v", env.Error)
	}
}
