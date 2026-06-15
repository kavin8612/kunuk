-- Kunuk — Migrazione 0001: schema iniziale + Row-Level Security (task 0.8).
--
-- Artefatto vivo del modello dati (doc 11) e companion di schema.sql. Eseguita dal
-- ruolo kunuk_migrations (DDL); i ruoli e le estensioni nascono prima, nell'init
-- (scripts/db/init/, superuser). Le colonne BYTEA "ciphertext" sono opache al server
-- (zero-knowledge): mai chiavi né plaintext. RLS isola gli utenti dentro il DB (SR-32).

-- +goose Up

-- Trigger condiviso per updated_at.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION set_updated_at() RETURNS trigger AS $$
BEGIN
  NEW.updated_at = now();
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd

-- account: nessuna password né hash (verificatore via password 2SKD + passkey).
CREATE TABLE account (
    id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email             CITEXT NOT NULL UNIQUE,
    password_verifier BYTEA  NOT NULL,        -- verificatore della via password (doc 16 §3)
    kdf_params        JSONB  NOT NULL,
    recovery_pubkey   BYTEA  NOT NULL,        -- Ed25519: prova di possesso del recupero
    status            TEXT   NOT NULL DEFAULT 'active',
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TRIGGER trg_account_updated BEFORE UPDATE ON account
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- device: la busta biometria (wrap_DK(VK)) NON è qui, vive sul dispositivo.
CREATE TABLE device (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    account_id  UUID NOT NULL REFERENCES account(id) ON DELETE CASCADE,
    name        TEXT NOT NULL,
    platform    TEXT NOT NULL CHECK (platform IN ('desktop','ios','android','web','cli')),
    public_key  BYTEA NOT NULL,
    push_token  TEXT,
    last_seen   TIMESTAMPTZ,
    revoked     BOOLEAN NOT NULL DEFAULT false,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_device_account ON device(account_id);

-- vault: MVP un vault personale per account. wrapped_signing_key = seme Ed25519 della
-- chiave di firma avvolto dalla VK (doc 16 §6), persistito accanto al manifest.
CREATE TABLE vault (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    account_id          UUID NOT NULL UNIQUE REFERENCES account(id) ON DELETE CASCADE,
    manifest            BYTEA NOT NULL,
    manifest_pubkey     BYTEA NOT NULL,       -- Ed25519
    signature           BYTEA NOT NULL,
    wrapped_signing_key BYTEA NOT NULL,       -- busta della chiave di firma (doc 16 §6)
    version             INTEGER NOT NULL DEFAULT 1,
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TRIGGER trg_vault_updated BEFORE UPDATE ON vault
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- envelope: buste della VK sul server (password, passkey, recovery). La biometria no.
CREATE TABLE envelope (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    account_id  UUID NOT NULL REFERENCES account(id) ON DELETE CASCADE,
    type        TEXT NOT NULL CHECK (type IN ('password','passkey','recovery')),
    wrapped_vk  BYTEA NOT NULL,
    params      JSONB,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (account_id, type)
);
CREATE INDEX idx_envelope_account ON envelope(account_id);
CREATE TRIGGER trg_envelope_updated BEFORE UPDATE ON envelope
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- item: voci del vault cifrate (il tipo della voce è dentro il ciphertext, SR-25).
CREATE TABLE item (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    vault_id    UUID NOT NULL REFERENCES vault(id) ON DELETE CASCADE,
    ciphertext  BYTEA NOT NULL,
    wrapped_cek BYTEA NOT NULL,
    deleted     BOOLEAN NOT NULL DEFAULT false,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_item_vault ON item(vault_id);
CREATE INDEX idx_item_vault_updated ON item(vault_id, updated_at);
CREATE TRIGGER trg_item_updated BEFORE UPDATE ON item
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- sync_change: delta CRDT cifrati; id monotono usato come cursore di pull.
CREATE TABLE sync_change (
    id         BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    vault_id   UUID NOT NULL REFERENCES vault(id) ON DELETE CASCADE,
    device_id  UUID REFERENCES device(id) ON DELETE SET NULL,
    ciphertext BYTEA NOT NULL,
    clock      TEXT  NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_sync_vault_id ON sync_change(vault_id, id);

-- recovery_request: implementa ritardo (unlock_at) e annullamento.
CREATE TABLE recovery_request (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    account_id   UUID NOT NULL REFERENCES account(id) ON DELETE CASCADE,
    requested_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    unlock_at    TIMESTAMPTZ NOT NULL,
    status       TEXT NOT NULL DEFAULT 'pending'
                 CHECK (status IN ('pending','cancelled','completed')),
    notified     BOOLEAN NOT NULL DEFAULT false
);
CREATE INDEX idx_recovery_account ON recovery_request(account_id);
CREATE INDEX idx_recovery_status  ON recovery_request(status);

-- breach_email_monitor: eccezione zero-knowledge dichiarata, minimizzata.
CREATE TABLE breach_email_monitor (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    account_id   UUID NOT NULL REFERENCES account(id) ON DELETE CASCADE,
    email_ref    TEXT NOT NULL,
    last_checked TIMESTAMPTZ,
    status       TEXT NOT NULL DEFAULT 'active',
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_breach_account ON breach_email_monitor(account_id);

-- plan / account_plan: motore di entitlement (ADR-0016). I piani sono dati.
CREATE TABLE plan (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name         TEXT NOT NULL UNIQUE,
    entitlements JSONB NOT NULL,
    trial_days   INTEGER,
    active       BOOLEAN NOT NULL DEFAULT true,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TRIGGER trg_plan_updated BEFORE UPDATE ON plan
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TABLE account_plan (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    account_id UUID NOT NULL REFERENCES account(id) ON DELETE CASCADE,
    plan_id    UUID NOT NULL REFERENCES plan(id),
    starts_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_account_plan_account ON account_plan(account_id);

-- audit_event: log eventi, nessun segreto (base NIS2).
CREATE TABLE audit_event (
    id         BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    account_id UUID REFERENCES account(id) ON DELETE SET NULL,
    type       TEXT NOT NULL,
    metadata   JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_audit_account ON audit_event(account_id);
CREATE INDEX idx_audit_created ON audit_event(created_at);

-- ---------------------------------------------------------------------------
-- Row-Level Security (SR-32, ADR-0017). I ruoli kunuk_app/kunuk_migrations nascono
-- nell'init (con password da .env). A ogni richiesta autenticata il backend esegue
-- SET LOCAL app.account_id = '<uuid>'; le policy filtrano le righe dentro il DB.
-- ---------------------------------------------------------------------------

-- Helper: account corrente della sessione applicativa.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION current_account_id() RETURNS uuid AS $$
  SELECT NULLIF(current_setting('app.account_id', true), '')::uuid
$$ LANGUAGE sql STABLE;
-- +goose StatementEnd

-- Tabelle con account_id diretto.
ALTER TABLE account              ENABLE ROW LEVEL SECURITY;
ALTER TABLE device               ENABLE ROW LEVEL SECURITY;
ALTER TABLE vault                ENABLE ROW LEVEL SECURITY;
ALTER TABLE envelope             ENABLE ROW LEVEL SECURITY;
ALTER TABLE recovery_request     ENABLE ROW LEVEL SECURITY;
ALTER TABLE breach_email_monitor ENABLE ROW LEVEL SECURITY;
ALTER TABLE account_plan         ENABLE ROW LEVEL SECURITY;

CREATE POLICY p_account  ON account              USING (id = current_account_id());
CREATE POLICY p_device   ON device               USING (account_id = current_account_id());
CREATE POLICY p_vault    ON vault                USING (account_id = current_account_id());
CREATE POLICY p_envelope ON envelope             USING (account_id = current_account_id());
CREATE POLICY p_recovery ON recovery_request     USING (account_id = current_account_id());
CREATE POLICY p_breach   ON breach_email_monitor USING (account_id = current_account_id());
CREATE POLICY p_acplan   ON account_plan         USING (account_id = current_account_id());

-- Tabelle scoperte via vault.
ALTER TABLE item        ENABLE ROW LEVEL SECURITY;
ALTER TABLE sync_change ENABLE ROW LEVEL SECURITY;
CREATE POLICY p_item ON item USING (
  vault_id IN (SELECT id FROM vault WHERE account_id = current_account_id()));
CREATE POLICY p_sync ON sync_change USING (
  vault_id IN (SELECT id FROM vault WHERE account_id = current_account_id()));

-- plan: catalogo gestito dall'admin; gli utenti leggono solo i piani attivi.
ALTER TABLE plan ENABLE ROW LEVEL SECURITY;
CREATE POLICY p_plan_read ON plan FOR SELECT USING (active);

-- audit_event: append-only per l'app; lettura riservata ad amministrazione/compliance.
ALTER TABLE audit_event ENABLE ROW LEVEL SECURITY;
CREATE POLICY p_audit_insert ON audit_event FOR INSERT
  WITH CHECK (account_id IS NULL OR account_id = current_account_id());

-- Privilegi del ruolo applicativo: solo DML, soggetto a RLS (niente DDL, niente BYPASSRLS).
GRANT USAGE ON SCHEMA public TO kunuk_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO kunuk_app;

-- +goose Down
DROP TABLE IF EXISTS audit_event          CASCADE;
DROP TABLE IF EXISTS account_plan          CASCADE;
DROP TABLE IF EXISTS plan                  CASCADE;
DROP TABLE IF EXISTS breach_email_monitor  CASCADE;
DROP TABLE IF EXISTS recovery_request      CASCADE;
DROP TABLE IF EXISTS sync_change           CASCADE;
DROP TABLE IF EXISTS item                  CASCADE;
DROP TABLE IF EXISTS envelope              CASCADE;
DROP TABLE IF EXISTS vault                 CASCADE;
DROP TABLE IF EXISTS device                CASCADE;
DROP TABLE IF EXISTS account               CASCADE;
DROP FUNCTION IF EXISTS current_account_id();
DROP FUNCTION IF EXISTS set_updated_at();
