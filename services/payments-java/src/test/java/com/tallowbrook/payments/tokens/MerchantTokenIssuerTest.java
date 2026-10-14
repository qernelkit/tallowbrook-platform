package com.tallowbrook.payments.tokens;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.tallowbrook.payments.config.PaymentsProperties;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;

import org.junit.jupiter.api.Test;

import java.net.URI;
import java.security.KeyPair;
import java.time.Duration;
import java.util.Set;

class MerchantTokenIssuerTest {

    private static final PaymentsProperties.Tokens CONFIG =
            new PaymentsProperties.Tokens(
                    URI.create("https://payments.tallowbrook.example"),
                    null,
                    Duration.ofMinutes(15));

    @Test
    void issuedTokenCarriesMerchantAndScopes() {
        KeyPair keys = Jwts.SIG.ES256.keyPair().build();
        MerchantTokenIssuer issuer = new MerchantTokenIssuer(CONFIG, keys.getPrivate());

        String token = issuer.issue("mer_1001", Set.of("payouts:read"));

        Claims claims =
                Jwts.parser()
                        .verifyWith(keys.getPublic())
                        .build()
                        .parseSignedClaims(token)
                        .getPayload();
        assertEquals("mer_1001", claims.getSubject());
        assertEquals("payouts:read", claims.get("scp", String.class));
        assertEquals("https://payments.tallowbrook.example", claims.getIssuer());
    }

    @Test
    void refusesTokensWithoutScopes() {
        MerchantTokenIssuer issuer = new MerchantTokenIssuer(CONFIG, null);
        assertThrows(IllegalArgumentException.class, () -> issuer.issue("mer_1001", Set.of()));
    }
}
