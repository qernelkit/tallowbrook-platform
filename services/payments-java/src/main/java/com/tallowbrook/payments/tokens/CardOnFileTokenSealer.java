package com.tallowbrook.payments.tokens;

import com.tallowbrook.payments.card.CardVaultKeys;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;

import org.springframework.stereotype.Component;

import java.security.GeneralSecurityException;
import java.time.Instant;
import java.util.Date;

import javax.crypto.SecretKey;

/**
 * Card-on-file tokens handed to merchants for repeat charges. They are opaque to the merchant: the
 * vault reference and merchant id travel encrypted under the vault key-encryption key.
 */
@Component
public class CardOnFileTokenSealer {

    private final CardVaultKeys keys;

    public CardOnFileTokenSealer(CardVaultKeys keys) {
        this.keys = keys;
    }

    public record CardOnFile(String vaultToken, String merchantId) {}

    public String seal(CardOnFile card) throws GeneralSecurityException {
        SecretKey vaultKek = keys.vaultKek();
        return Jwts.builder()
                .subject(card.vaultToken())
                .claim("mid", card.merchantId())
                .issuedAt(Date.from(Instant.now()))
                .encryptWith(
                        vaultKek,
                        Jwts.KEY.A256KW, // wraps the per-token content key
                        Jwts.ENC.A256GCM) // encrypts the claims
                .compact();
    }

    public CardOnFile open(String sealed, String expectedMerchantId)
            throws GeneralSecurityException {
        Claims claims =
                Jwts.parser()
                        .decryptWith(keys.vaultKek())
                        .build()
                        .parseEncryptedClaims(sealed)
                        .getPayload();
        String merchantId = claims.get("mid", String.class);
        if (!expectedMerchantId.equals(merchantId)) {
            throw new IllegalArgumentException("Card-on-file token belongs to another merchant");
        }
        return new CardOnFile(claims.getSubject(), merchantId);
    }
}
