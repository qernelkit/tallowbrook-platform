-- Storefront: gift card codes stop being stored in clear, the customer e-mail
-- gets a lookup column, and the catalogue cache gets a stable key.
-- @gift_key is supplied by the deploy job (mysql --init-command) from the
-- storefront secret; it is never written to the repository.

-- gift_cards and storefront_customers come from earlier migrations in existing
-- databases; repeated here so a fresh schema build works from this file alone.
CREATE TABLE IF NOT EXISTS gift_cards (
    id bigint unsigned NOT NULL AUTO_INCREMENT PRIMARY KEY,
    code varchar(32) NULL,
    balance_minor int NOT NULL DEFAULT 0,
    currency char(3) NOT NULL DEFAULT 'USD',
    created_at timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS storefront_customers (
    id bigint unsigned NOT NULL AUTO_INCREMENT PRIMARY KEY,
    email varchar(254) NOT NULL,
    created_at timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP
);

ALTER TABLE gift_cards
    ADD COLUMN code_ciphertext varbinary(64) NULL,
    ADD COLUMN code_iv varbinary(16) NULL,
    ADD COLUMN code_export varchar(128) NULL;

ALTER TABLE storefront_customers
    ADD COLUMN email_lookup binary(64) NULL,
    ADD INDEX storefront_customers_email_lookup_idx (email_lookup);

CREATE TABLE catalogue_entries (
    sku varchar(40) NOT NULL,
    locale varchar(10) NOT NULL,
    title varchar(200) NOT NULL,
    price_minor int NOT NULL,
    catalogue_cache_key char(32) AS (MD5(CONCAT(sku, ':', locale))) STORED,
    shard_no tinyint unsigned AS (CRC32(sku) % 16) STORED,
    PRIMARY KEY (sku, locale),
    UNIQUE KEY catalogue_entries_cache_key (catalogue_cache_key)
);

SET SESSION block_encryption_mode = 'aes-256-cbc';
SET @gift_iv = RANDOM_BYTES(16);

UPDATE gift_cards
SET code_ciphertext = AES_ENCRYPT(code, @gift_key, @gift_iv),
    code_iv = @gift_iv,
    code_export = TO_BASE64(code_ciphertext),
    code = NULL
WHERE code IS NOT NULL;

UPDATE storefront_customers
SET email_lookup = UNHEX(SHA2(LOWER(email), 512))
WHERE email_lookup IS NULL;
