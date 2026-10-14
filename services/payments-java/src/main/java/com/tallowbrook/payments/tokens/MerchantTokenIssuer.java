package com.tallowbrook.payments.tokens;

import com.tallowbrook.payments.config.PaymentsProperties;

import io.jsonwebtoken.Jwts;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

/** Short-lived API tokens for merchant back-office integrations. */
@Service
public class MerchantTokenIssuer {

    private final PaymentsProperties.Tokens config;
    private final PrivateKey issuerKey;

    @Autowired
    public MerchantTokenIssuer(PaymentsProperties properties)
            throws IOException, GeneralSecurityException {
        this(properties.tokens(), readIssuerKey(properties.tokens().tokenSigningKey()));
    }

    MerchantTokenIssuer(PaymentsProperties.Tokens config, PrivateKey issuerKey) {
        this.config = config;
        this.issuerKey = issuerKey;
    }

    public String issue(String merchantId, Set<String> scopes) {
        if (scopes.isEmpty()) {
            throw new IllegalArgumentException("A merchant token needs at least one scope");
        }
        Instant now = Instant.now();
        return Jwts.builder()
                .issuer(config.issuer().toString())
                .subject(merchantId)
                .claim("scp", String.join(" ", scopes))
                .issuedAt(Date.from(now))
                .expiration(Date.from(now.plus(config.ttl())))
                .id(UUID.randomUUID().toString())
                .signWith(issuerKey)
                .compact();
    }

    static PrivateKey readIssuerKey(Path pemFile) throws IOException, GeneralSecurityException {
        String body =
                Files.readAllLines(pemFile).stream()
                        .filter(line -> !line.startsWith("-----"))
                        .collect(Collectors.joining());
        byte[] der = Base64.getDecoder().decode(body);
        return KeyFactory.getInstance("EC").generatePrivate(new PKCS8EncodedKeySpec(der));
    }
}
