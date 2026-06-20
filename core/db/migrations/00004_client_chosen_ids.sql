-- Kunuk — Migrazione 0004: account_id e vault_id SCELTI dal client in registrazione (task 0.11).
-- Contesto: il core lega `account_id` nelle AAD/derivazioni (verificatore AV e buste VK,
-- doc 16 §3-4) e `vault_id` nelle AAD di item/manifest (doc 16 §5-6). Prima il server GENERAVA
-- `account.id`/`vault.id` (UUID random) e non li esponeva: un dispositivo "vergine" (solo email +
-- password + Secret Key) non poteva ricostruirli → non poteva derivare l'AV né aprire le buste.
-- Ora gli id sono scelti dal client (come `item.id`, migrazione 00003) e PERSISTITI così come
-- arrivano; il server li restituisce a login/start (con decoy anti-enum, SR-26, lato Go) e su
-- GET /vault. Esporre `account_id` non indebolisce nulla: la robustezza poggia sul 2SKD (Secret
-- Key 128-bit mai sul server, ADR-0006). Vedi ADR-0020.
--
-- L'`EXCEPTION WHEN unique_violation` preesistente copre ora anche le collisioni di
-- `account_id`/`vault_id` (oltre all'email): ritorna NULL → 201 uniforme, anti-enum preservato.

-- +goose Up
DROP FUNCTION IF EXISTS register_account(citext,bytea,jsonb,bytea,bytea,bytea,bytea,bytea,bytea,bytea,bytea,integer,bytea,jsonb);

-- +goose StatementBegin
CREATE FUNCTION register_account(
    p_account_id        UUID,
    p_vault_id          UUID,
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
BEGIN
    INSERT INTO account (id, email, password_verifier, kdf_params, recovery_pubkey)
        VALUES (p_account_id, p_email, p_password_verifier, p_kdf_params, p_recovery_pubkey);

    INSERT INTO envelope (account_id, type, wrapped_vk, params)
        VALUES (p_account_id, 'password', p_password_wrapped, p_kdf_params);
    IF p_passkey_wrapped IS NOT NULL THEN
        INSERT INTO envelope (account_id, type, wrapped_vk, params)
            VALUES (p_account_id, 'passkey', p_passkey_wrapped, NULL);
    END IF;
    INSERT INTO envelope (account_id, type, wrapped_vk, params)
        VALUES (p_account_id, 'recovery', p_recovery_wrapped, NULL);

    INSERT INTO vault (id, account_id, manifest, manifest_pubkey, signature, wrapped_signing_key, version)
        VALUES (p_vault_id, p_account_id, p_manifest, p_manifest_pubkey, p_signature, p_wrapped_signing, p_version);

    IF p_cred_id IS NOT NULL THEN
        INSERT INTO webauthn_credential (account_id, credential_id, data)
            VALUES (p_account_id, p_cred_id, p_cred_data);
    END IF;

    RETURN p_account_id;
EXCEPTION WHEN unique_violation THEN
    RETURN NULL;  -- email / account_id / vault_id già presenti: stessa risposta (anti-enum)
END;
$$;
-- +goose StatementEnd

-- Privilegi: solo kunuk_app, mai PUBLIC (SR-32). DROP+CREATE azzera i GRANT del 00002 e la
-- nuova funzione nasce eseguibile da PUBLIC per default → vanno ristabiliti esplicitamente.
REVOKE ALL ON FUNCTION register_account(UUID,UUID,CITEXT,BYTEA,JSONB,BYTEA,BYTEA,BYTEA,BYTEA,BYTEA,BYTEA,BYTEA,BYTEA,INTEGER,BYTEA,JSONB) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION register_account(UUID,UUID,CITEXT,BYTEA,JSONB,BYTEA,BYTEA,BYTEA,BYTEA,BYTEA,BYTEA,BYTEA,BYTEA,INTEGER,BYTEA,JSONB) TO kunuk_app;

-- +goose Down
DROP FUNCTION IF EXISTS register_account(uuid,uuid,citext,bytea,jsonb,bytea,bytea,bytea,bytea,bytea,bytea,bytea,bytea,integer,bytea,jsonb);

-- +goose StatementBegin
CREATE FUNCTION register_account(
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
    RETURN NULL;
END;
$$;
-- +goose StatementEnd

REVOKE ALL ON FUNCTION register_account(CITEXT,BYTEA,JSONB,BYTEA,BYTEA,BYTEA,BYTEA,BYTEA,BYTEA,BYTEA,BYTEA,INTEGER,BYTEA,JSONB) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION register_account(CITEXT,BYTEA,JSONB,BYTEA,BYTEA,BYTEA,BYTEA,BYTEA,BYTEA,BYTEA,BYTEA,INTEGER,BYTEA,JSONB) TO kunuk_app;
