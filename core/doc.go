// Package core è il backend di Kunuk: monolite modulare che espone solo
// ciphertext (zero-knowledge, ADR-0002) con PostgreSQL come unico datastore
// sotto RLS (ADR-0011, SR-32).
//
// TODO(task-0.9): implementazione dei moduli auth/accounts/vault-storage e
// dell'entrypoint dell'API — placeholder del bootstrap (task 0.1). Questo file
// esiste solo per dare alla toolchain Go un package valido da compilare,
// testare e analizzare finché non arriva il codice reale.
package core
