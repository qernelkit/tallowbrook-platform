package com.tallowbrook.payments.card;

import org.bouncycastle.crypto.fpe.FPEFF1Engine;
import org.bouncycastle.crypto.params.FPEParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;

/**
 * Format-preserving PAN tokens: the BIN and the last four digits stay readable for merchants, the
 * digits in between are replaced. The merchant id is the tweak, so the same card gets a different
 * token at each merchant.
 */
@Component
public class PanTokenizer {

    private static final int RADIX = 10;
    private static final int KEEP_LEADING = 6;
    private static final int KEEP_TRAILING = 4;

    private final byte[] tokenizationKey;

    @Autowired
    public PanTokenizer(CardVaultKeys keys) {
        this(keys.tokenizationKey());
    }

    PanTokenizer(byte[] tokenizationKey) {
        this.tokenizationKey = tokenizationKey.clone();
    }

    public String tokenize(String pan, String merchantId) {
        return transform(pan, merchantId, true);
    }

    public String detokenize(String token, String merchantId) {
        return transform(token, merchantId, false);
    }

    private String transform(String number, String merchantId, boolean forward) {
        if (!PanChecks.digitsOnly(number) || !PanChecks.plausibleLength(number)) {
            throw new IllegalArgumentException("Not a card number");
        }
        int end = number.length() - KEEP_TRAILING;
        byte[] middle = new byte[end - KEEP_LEADING];
        for (int i = 0; i < middle.length; i++) {
            middle[i] = (byte) (number.charAt(KEEP_LEADING + i) - '0');
        }
        byte[] out = new byte[middle.length];
        engine(forward, merchantId).processBlock(middle, 0, middle.length, out, 0);
        StringBuilder result = new StringBuilder(number.substring(0, KEEP_LEADING));
        for (byte digit : out) {
            result.append((char) ('0' + digit));
        }
        return result.append(number.substring(end)).toString();
    }

    private FPEFF1Engine engine(boolean forward, String merchantId) {
        FPEFF1Engine engine = new FPEFF1Engine();
        byte[] tweak = merchantId.getBytes(StandardCharsets.UTF_8);
        engine.init(forward, new FPEParameters(new KeyParameter(tokenizationKey), RADIX, tweak));
        return engine;
    }
}
