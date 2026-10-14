package com.tallowbrook.payments.card;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

/**
 * The token to PAN table. Rows are sharded by merchant and region; the PAN itself is stored sealed,
 * and a keyed lookup index lets us return the existing token when a merchant sends the same card
 * twice.
 */
@Component
public class TokenVault {

    private static final Logger log = LoggerFactory.getLogger(TokenVault.class);
    private static final int SHARDS = 64;

    private final JdbcClient jdbc;
    private final CardDataCipher cardData;
    private final PanTokenizer tokenizer;
    private final byte[] indexKey;

    public TokenVault(
            JdbcClient jdbc, CardDataCipher cardData, PanTokenizer tokenizer, CardVaultKeys keys) {
        this.jdbc = jdbc;
        this.cardData = cardData;
        this.tokenizer = tokenizer;
        this.indexKey = keys.panIndexKey();
    }

    public record VaultRow(String token, byte[] sealedPan) {}

    public String tokenFor(
            String merchantId, String region, String pan, SecretKey dataKey, String dataKeyId)
            throws GeneralSecurityException {
        if (!PanChecks.luhnValid(pan)) {
            throw new IllegalArgumentException("Card number fails the check digit");
        }
        int shard = Math.floorMod(Objects.hash(merchantId, region), SHARDS);
        Mac indexMac = Mac.getInstance("HmacSHA256");
        indexMac.init(new SecretKeySpec(indexKey, "HmacSHA256"));
        String panIndex =
                HexFormat.of().formatHex(indexMac.doFinal(pan.getBytes(StandardCharsets.US_ASCII)));
        Optional<String> existing =
                jdbc.sql(
                                """
                                select token from card_vault
                                where shard = ? and merchant_id = ? and pan_index = ?\
                                """)
                        .params(shard, merchantId, panIndex)
                        .query(String.class)
                        .optional();
        if (existing.isPresent()) {
            return existing.get();
        }
        String token = tokenizer.tokenize(pan, merchantId);
        byte[] sealedPan =
                cardData.seal(
                        dataKey,
                        pan.getBytes(StandardCharsets.US_ASCII),
                        token.getBytes(StandardCharsets.US_ASCII));
        jdbc.sql(
                        """
                        insert into card_vault (shard, merchant_id, token, pan_index, sealed_pan, data_key_id)
                        values (?, ?, ?, ?, ?, ?)\
                        """)
                .params(shard, merchantId, token, panIndex, sealedPan, dataKeyId)
                .update();
        log.info(
                "New token for merchant {} in shard {} ({})",
                merchantId,
                shard,
                PanChecks.masked(pan));
        return token;
    }

    public String reveal(VaultRow row, SecretKey dataKey) throws GeneralSecurityException {
        byte[] pan =
                cardData.open(
                        dataKey, row.sealedPan(), row.token().getBytes(StandardCharsets.US_ASCII));
        return new String(pan, StandardCharsets.US_ASCII);
    }

    /**
     * Chargeback exports reveal thousands of rows under one data key; one cipher object is reused
     * for the whole batch instead of going through {@link #reveal} per row.
     */
    public List<String> revealBatch(List<VaultRow> rows, SecretKey dataKey)
            throws GeneralSecurityException {
        Cipher batch = Cipher.getInstance(CardDataCipher.TRANSFORMATION);
        List<String> pans = new ArrayList<>(rows.size());
        for (VaultRow row : rows) {
            byte[] stored = row.sealedPan();
            batch.init(
                    Cipher.DECRYPT_MODE,
                    dataKey,
                    CardDataCipher.parameters(Arrays.copyOf(stored, CardDataCipher.IV_BYTES)));
            batch.updateAAD(row.token().getBytes(StandardCharsets.US_ASCII));
            byte[] pan =
                    batch.doFinal(
                            stored,
                            CardDataCipher.IV_BYTES,
                            stored.length - CardDataCipher.IV_BYTES);
            pans.add(new String(pan, StandardCharsets.US_ASCII));
        }
        return pans;
    }
}
