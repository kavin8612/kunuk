-- Kunuk — Migrazione 0002: sessioni, credenziali WebAuthn, verifica email e challenge
-- (task 0.9). Aggiunge ciò che il backend (auth/accounts/vault-storage) richiede e che lo
-- schema 0.8 non aveva. I flussi pre-autenticazione (registrazione/login/verifica-email/
-- sessione/challenge) NON hanno ancora un account in sessione: passano da funzioni
-- SECURITY DEFINER dedicate (owner kunuk_migrations), mai da kunuk_app con RLS aperta
-- (schema.sql §RLS, SR-32). Il backend tratta solo ciphertext/verificatori (zero-knowledge).

-- +goose Up

-- session: token opachi, memorizzati solo come hash (SR-31), revocabili.
CREATE TABLE session (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    account_id   UUID NOT NULL REFERENCES account(id) ON DELETE CASCADE,
    token_hash   BYTEA NOT NULL UNIQUE,       -- SHA-256 del token (mai il token in chiaro)
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at   TIMESTAMPTZ NOT NULL,
    revoked      BOOLEAN NOT NULL DEFAULT false
);
CREATE INDEX idx_session_account ON session(account_id);

-- webauthn_credential: chiave pubblica della passkey per verificare le assertion.
CREATE TABLE webauthn_credential (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    account_id    UUID NOT NULL REFERENCES account(id) ON DELETE CASCADE,
    credential_id BYTEA NOT NULL UNIQUE,      -- id della credential WebAuthn
    data          JSONB NOT NULL,             -- credential serializzata (go-webauthn)
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_webauthn_cred_account ON webauthn_credential(account_id);

-- email_verification_token: token di verifica email, memorizzato come hash, consumabile.
CREATE TABLE email_verification_token (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    account_id  UUID NOT NULL REFERENCES account(id) ON DELETE CASCADE,
    token_hash  BYTEA NOT NULL UNIQUE,
    expires_at  TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- webauthn_challenge: stato effimero della cerimonia (SessionData go-webauthn) tra start e
-- finish, indicizzato da un handle opaco. Accessibile solo via le funzioni SECURITY DEFINER.
CREATE TABLE webauthn_challenge (
    handle       BYTEA PRIMARY KEY,
    session_data JSONB NOT NULL,
    expires_at   TIMESTAMPTZ NOT NULL,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- RLS sulle tabelle utente (come le altre, doc 18 §9 / SR-32).
ALTER TABLE session                  ENABLE ROW LEVEL SECURITY;
ALTER TABLE webauthn_credential       ENABLE ROW LEVEL SECURITY;
ALTER TABLE email_verification_token  ENABLE ROW LEVEL SECURITY;
ALTER TABLE webauthn_challenge         ENABLE ROW LEVEL SECURITY;

CREATE POLICY p_session ON session                         USING (account_id = current_account_id());
CREATE POLICY p_webauthn_cred ON webauthn_credential       USING (account_id = current_account_id());
CREATE POLICY p_email_token ON email_verification_token    USING (account_id = current_account_id());
-- webauthn_challenge non ha account_id: nessuna policy permissiva → kunuk_app non vede righe.

-- Privilegi: il blanket GRANT della 00001 non copre le tabelle nuove. session/credential/
-- email-token sono accedute da kunuk_app (sotto RLS, per la cascade e i percorsi self-service
-- futuri); webauthn_challenge solo via funzioni → nessun DML diretto.
GRANT SELECT, INSERT, UPDATE, DELETE ON session, webauthn_credential, email_verification_token TO kunuk_app;
REVOKE ALL ON webauthn_challenge FROM kunuk_app;

-- ── Funzioni pre-autenticazione (SECURITY DEFINER, owner kunuk_migrations) ──────────────
-- Bypassano la RLS in modo ristretto e audibile; solo query parametrizzate (SR-30).

-- register_account: crea account + 3 buste + vault + credenziale passkey in modo atomico.
-- Su email già esistente ritorna NULL (anti-enumeration, SR-26): nessun errore distinguibile.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION register_account(
    p_email             CITEXT,
    p_password_verifier BYTEA,
    p_kdf_params        JSONB,
    p_recovery_pubkey   BYTEA,
    p_password_wrapped  BYTEA,
    p_passkey_wrapped   BYTEA,
    p_recovery_wrapped  BYTEA,
    p_manifest          BYTEA,
    p_manifest_pubkey   BYTEA,
    p_signature         BYTEA,
    p_wrapped_signing   BYTEA,
    p_version           INTEGER,
    p_cred_id           BYTEA,
    p_cred_data         JSONB
) RETURNS UUID
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE
    v_account_id UUID;
BEGIN
    INSERT INTO account (email, password_verifier, kdf_params, recovery_pubkey)
        VALUES (p_email, p_password_verifier, p_kdf_params, p_recovery_pubkey)
        RETURNING id INTO v_account_id;

    INSERT INTO envelope (account_id, type, wrapped_vk, params)
        VALUES (v_account_id, 'password', p_password_wrapped, p_kdf_params);
    IF p_passkey_wrapped IS NOT NULL THEN
        INSERT INTO envelope (account_id, type, wrapped_vk, params)
            VALUES (v_account_id, 'passkey', p_passkey_wrapped, NULL);
    END IF;
    INSERT INTO envelope (account_id, type, wrapped_vk, params)
        VALUES (v_account_id, 'recovery', p_recovery_wrapped, NULL);

    INSERT INTO vault (account_id, manifest, manifest_pubkey, signature, wrapped_signing_key, version)
        VALUES (v_account_id, p_manifest, p_manifest_pubkey, p_signature, p_wrapped_signing, p_version);

    IF p_cred_id IS NOT NULL THEN
        INSERT INTO webauthn_credential (account_id, credential_id, data)
            VALUES (v_account_id, p_cred_id, p_cred_data);
    END IF;

    RETURN v_account_id;
EXCEPTION WHEN unique_violation THEN
    RETURN NULL;  -- email già registrata: stessa risposta di una registrazione nuova
END;
$$;
-- +goose StatementEnd

-- login_material: materiale per il login di un'email non autenticata (verificatore, kdf,
-- credenziali). Il chiamante (Go) gestisce il decoy per email inesistente (anti-enum).
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION login_material(p_email CITEXT)
RETURNS TABLE (account_id UUID, password_verifier BYTEA, kdf_params JSONB, credentials JSONB)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
BEGIN
    RETURN QUERY
        SELECT a.id, a.password_verifier, a.kdf_params,
               COALESCE(
                   (SELECT jsonb_agg(jsonb_build_object('credential_id', encode(c.credential_id, 'base64'), 'data', c.data))
                      FROM webauthn_credential c WHERE c.account_id = a.id),
                   '[]'::jsonb)
          FROM account a
         WHERE a.email = p_email;
END;
$$;
-- +goose StatementEnd

-- session_create: crea una sessione subito dopo il login riuscito.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION session_create(p_account_id UUID, p_token_hash BYTEA, p_expires_at TIMESTAMPTZ)
RETURNS UUID
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE
    v_id UUID;
BEGIN
    INSERT INTO session (account_id, token_hash, expires_at)
        VALUES (p_account_id, p_token_hash, p_expires_at)
        RETURNING id INTO v_id;
    RETURN v_id;
END;
$$;
-- +goose StatementEnd

-- session_lookup: convalida un token per ogni richiesta (pre-account). Aggiorna last_seen.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION session_lookup(p_token_hash BYTEA)
RETURNS TABLE (account_id UUID, session_id UUID)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
BEGIN
    RETURN QUERY
        UPDATE session s SET last_seen_at = now()
         WHERE s.token_hash = p_token_hash
           AND NOT s.revoked
           AND s.expires_at > now()
        RETURNING s.account_id, s.id;
END;
$$;
-- +goose StatementEnd

-- verify_email: consuma un token di verifica email e attiva l'account.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION verify_email(p_token_hash BYTEA)
RETURNS BOOLEAN
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE
    v_account_id UUID;
BEGIN
    UPDATE email_verification_token
       SET consumed_at = now()
     WHERE token_hash = p_token_hash
       AND consumed_at IS NULL
       AND expires_at > now()
     RETURNING account_id INTO v_account_id;
    IF v_account_id IS NULL THEN
        RETURN false;
    END IF;
    UPDATE account SET status = 'active' WHERE id = v_account_id;
    RETURN true;
END;
$$;
-- +goose StatementEnd

-- webauthn_challenge_store / consume: stato effimero della cerimonia (one-shot).
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION webauthn_challenge_store(p_handle BYTEA, p_session_data JSONB, p_expires_at TIMESTAMPTZ)
RETURNS VOID
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
BEGIN
    DELETE FROM webauthn_challenge WHERE expires_at < now();  -- pulizia opportunistica
    INSERT INTO webauthn_challenge (handle, session_data, expires_at)
        VALUES (p_handle, p_session_data, p_expires_at);
END;
$$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION webauthn_challenge_consume(p_handle BYTEA)
RETURNS JSONB
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE
    v_data JSONB;
BEGIN
    DELETE FROM webauthn_challenge
     WHERE handle = p_handle AND expires_at > now()
     RETURNING session_data INTO v_data;
    RETURN v_data;  -- NULL se assente/scaduta
END;
$$;
-- +goose StatementEnd

-- Solo kunuk_app può eseguirle; mai PUBLIC.
REVOKE ALL ON FUNCTION
    register_account(CITEXT,BYTEA,JSONB,BYTEA,BYTEA,BYTEA,BYTEA,BYTEA,BYTEA,BYTEA,BYTEA,INTEGER,BYTEA,JSONB),
    login_material(CITEXT),
    session_create(UUID,BYTEA,TIMESTAMPTZ),
    session_lookup(BYTEA),
    verify_email(BYTEA),
    webauthn_challenge_store(BYTEA,JSONB,TIMESTAMPTZ),
    webauthn_challenge_consume(BYTEA)
    FROM PUBLIC;
GRANT EXECUTE ON FUNCTION
    register_account(CITEXT,BYTEA,JSONB,BYTEA,BYTEA,BYTEA,BYTEA,BYTEA,BYTEA,BYTEA,BYTEA,INTEGER,BYTEA,JSONB),
    login_material(CITEXT),
    session_create(UUID,BYTEA,TIMESTAMPTZ),
    session_lookup(BYTEA),
    verify_email(BYTEA),
    webauthn_challenge_store(BYTEA,JSONB,TIMESTAMPTZ),
    webauthn_challenge_consume(BYTEA)
    TO kunuk_app;

-- +goose Down
DROP FUNCTION IF EXISTS webauthn_challenge_consume(BYTEA);
DROP FUNCTION IF EXISTS webauthn_challenge_store(BYTEA,JSONB,TIMESTAMPTZ);
DROP FUNCTION IF EXISTS verify_email(BYTEA);
DROP FUNCTION IF EXISTS session_lookup(BYTEA);
DROP FUNCTION IF EXISTS session_create(UUID,BYTEA,TIMESTAMPTZ);
DROP FUNCTION IF EXISTS login_material(CITEXT);
DROP FUNCTION IF EXISTS register_account(CITEXT,BYTEA,JSONB,BYTEA,BYTEA,BYTEA,BYTEA,BYTEA,BYTEA,BYTEA,BYTEA,INTEGER,BYTEA,JSONB);
DROP TABLE IF EXISTS webauthn_challenge CASCADE;
DROP TABLE IF EXISTS email_verification_token CASCADE;
DROP TABLE IF EXISTS webauthn_credential CASCADE;
DROP TABLE IF EXISTS session CASCADE;
