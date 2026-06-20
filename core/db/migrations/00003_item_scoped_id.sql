-- Kunuk — Migrazione 0003: id dell'item unico PER-VAULT, non globale (hardening task 0.10).
-- Contesto: l'id dell'item è scelto dal client perché legato nell'AAD `vault_id ‖ item_id`
-- del ciphertext (doc 16 §5). Con `id` come PRIMARY KEY globale, un INSERT di un id già
-- presente in UN ALTRO vault sollevava una violazione di unicità (SQLSTATE 23505 → 409)
-- anche sotto RLS: le unique constraint sono globali e scavalcano le policy di riga. Era un
-- oracolo di conferma-esistenza cross-tenant (in tensione con SR-26, anti-enumeration).
-- Rendendo la chiave primaria composita `(vault_id, id)` lo stesso UUID è ammesso in vault
-- diversi: nessuna collisione tra account → nessun oracolo; un duplicato nello STESSO vault
-- resta un conflitto legittimo (409). Nessuna FK referenzia `item(id)` (sync_change punta a
-- vault/device), quindi il cambio di PK è isolato.

-- +goose Up
ALTER TABLE item DROP CONSTRAINT item_pkey;
ALTER TABLE item ALTER COLUMN id SET NOT NULL;
ALTER TABLE item ADD CONSTRAINT item_pkey PRIMARY KEY (vault_id, id);

-- +goose Down
ALTER TABLE item DROP CONSTRAINT item_pkey;
ALTER TABLE item ADD CONSTRAINT item_pkey PRIMARY KEY (id);
