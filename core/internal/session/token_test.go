package session

import (
	"bytes"
	"testing"
)

func TestNewTokenUnico(t *testing.T) {
	t1, h1, err := NewToken()
	if err != nil {
		t.Fatalf("NewToken: %v", err)
	}
	t2, h2, err := NewToken()
	if err != nil {
		t.Fatalf("NewToken: %v", err)
	}
	if t1 == t2 {
		t.Fatal("due token devono differire")
	}
	if bytes.Equal(h1, h2) {
		t.Fatal("due hash devono differire")
	}
	if len(h1) != 32 {
		t.Fatalf("hash di %d byte, atteso 32 (SHA-256)", len(h1))
	}
}

func TestHashTokenStabile(t *testing.T) {
	tok, h, err := NewToken()
	if err != nil {
		t.Fatalf("NewToken: %v", err)
	}
	if !bytes.Equal(h, HashToken(tok)) {
		t.Fatal("HashToken deve riprodurre l'hash del token generato")
	}
}
