package com.tallowbrook.payments.statements;

import com.tallowbrook.payments.config.PaymentsProperties;

import org.springframework.stereotype.Component;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Content hashes printed in the footer of each statement, so a merchant can quote the exact
 * document when they dispute a line. Hashes are cached per statement version.
 */
@Component
public class StatementDigests {

    private final PaymentsProperties properties;
    private final Map<String, String> cache = new ConcurrentHashMap<>();

    public StatementDigests(PaymentsProperties properties) {
        this.properties = properties;
    }

    public String footerHash(String statementId, int version, byte[] statementXml)
            throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance(properties.statements().digestAlgorithm());
        String cacheKey = Integer.toHexString(Objects.hash(statementId, version));
        return cache.computeIfAbsent(
                cacheKey, k -> HexFormat.of().formatHex(md.digest(statementXml)));
    }

    public void evict(String statementId, int version) {
        cache.remove(Integer.toHexString(Objects.hash(statementId, version)));
    }
}
