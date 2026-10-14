-- Customer PII protection: phone numbers and label blobs are stored encrypted,
-- e-mail gets a lookup column so support can search without reading the
-- plaintext, and the partner portal password moves into the database.

CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- customers comes from V0003 in existing databases; this keeps fresh schema
-- builds (CI, local) working when V0021 runs on its own.
CREATE TABLE IF NOT EXISTS customers (
    customer_id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    display_name text NOT NULL,
    email text NOT NULL,
    phone text,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE OR REPLACE FUNCTION protect_pii(p_value text, p_key_b64 text)
RETURNS bytea
LANGUAGE plpgsql
AS $$
DECLARE
    c_pgp_options CONSTANT text := 'cipher-algo=aes256, compress-algo=1';
    v_key text;
BEGIN
    IF p_value IS NULL THEN
        RETURN NULL;
    END IF;
    v_key := convert_from(decode(p_key_b64, 'base64'), 'UTF8');
    RETURN pgp_sym_encrypt(p_value, v_key, c_pgp_options);
END;
$$;

CREATE OR REPLACE FUNCTION email_lookup_key(p_email text)
RETURNS text
LANGUAGE plpgsql
IMMUTABLE
AS $$
DECLARE
    c_lookup_digest CONSTANT text := 'sha256';
    v_digest bytea;
BEGIN
    v_digest := digest(lower(p_email), c_lookup_digest);
    RETURN encode(v_digest, 'hex');
END;
$$;

CREATE OR REPLACE FUNCTION carrier_callback_valid(p_payload bytea, p_secret bytea, p_signature bytea)
RETURNS boolean
LANGUAGE plpgsql
STABLE
AS $$
BEGIN
    RETURN hmac(p_payload, p_secret, 'sha1') = p_signature;
END;
$$;

CREATE OR REPLACE FUNCTION seal_label_blob(p_blob bytea, p_key bytea)
RETURNS bytea
LANGUAGE plpgsql
AS $$
BEGIN
    RETURN encrypt(p_blob, p_key, 'aes-cbc/pad:pkcs');
END;
$$;

CREATE OR REPLACE FUNCTION set_portal_password(p_password text)
RETURNS text
LANGUAGE sql
VOLATILE
RETURN crypt(p_password, gen_salt('bf', 10));

ALTER TABLE customers
    ADD COLUMN search_tokens tsvector GENERATED ALWAYS AS (to_tsvector('simple', coalesce(display_name, ''))) STORED,
    ADD COLUMN email_lookup text,
    ADD COLUMN phone_protected bytea,
    ADD COLUMN portal_login_hash text;

UPDATE customers SET email_lookup = email_lookup_key(email) WHERE email_lookup IS NULL;

CREATE INDEX customers_email_lookup_idx ON customers (email_lookup);
CREATE INDEX customers_search_idx ON customers USING gin (search_tokens);

CREATE TABLE IF NOT EXISTS shipping_labels (
    label_id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    customer_id bigint NOT NULL REFERENCES customers (customer_id),
    carrier_code text NOT NULL,
    label_sealed bytea NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);
