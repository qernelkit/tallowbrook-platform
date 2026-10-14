package com.tallowbrook.payments.card;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.security.SecureRandom;

class PanTokenizerTest {

    private static final String PAN = "4111111111111111";

    private PanTokenizer tokenizer;

    @BeforeEach
    void freshTokenizer() {
        byte[] runKey = new byte[32];
        new SecureRandom().nextBytes(runKey);
        tokenizer = new PanTokenizer(runKey);
    }

    @Test
    void keepsLengthBinAndLastFour() {
        String token = tokenizer.tokenize(PAN, "mer_1001");
        assertEquals(PAN.length(), token.length());
        assertEquals(PAN.substring(0, 6), token.substring(0, 6));
        assertEquals(PAN.substring(12), token.substring(12));
        assertTrue(PanChecks.digitsOnly(token));
    }

    @Test
    void roundTripsPerMerchant() {
        String token = tokenizer.tokenize(PAN, "mer_1001");
        assertEquals(PAN, tokenizer.detokenize(token, "mer_1001"));
        assertNotEquals(token, tokenizer.tokenize(PAN, "mer_2002"));
    }

    @Test
    void rejectsNonDigits() {
        assertThrows(
                IllegalArgumentException.class,
                () -> tokenizer.tokenize("4111-1111-1111-1111", "mer_1001"));
    }
}
