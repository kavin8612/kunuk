package main

import "testing"

// TestRunSenzaConfig verifica che l'avvio fallisca subito, in modo esplicito, se manca la
// configurazione obbligatoria (prima di toccare il DB). La sonda /health e il router sono
// testati in internal/httpserver.
func TestRunSenzaConfig(t *testing.T) {
	t.Setenv("KUNUK_DB_HOST", "") // forza almeno una variabile obbligatoria assente
	if err := run(); err == nil {
		t.Fatal("run() doveva fallire senza configurazione")
	}
}
