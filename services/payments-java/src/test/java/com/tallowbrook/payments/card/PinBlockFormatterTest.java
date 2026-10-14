package com.tallowbrook.payments.card;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Test;

import java.util.HexFormat;

class PinBlockFormatterTest {

    private final PinBlockFormatter formatter = new PinBlockFormatter();

    @Test
    void formatZeroCombinesPinAndAccountFields() {
        byte[] block = formatter.format0("1234", "4111111111111111");
        assertEquals("041225EEEEEEEEEE", HexFormat.of().withUpperCase().formatHex(block));
    }

    @Test
    void rejectsShortPins() {
        assertThrows(
                IllegalArgumentException.class, () -> formatter.format0("12", "4111111111111111"));
    }

    @Test
    void rejectsCardNumbersWithABadCheckDigit() {
        assertThrows(
                IllegalArgumentException.class,
                () -> formatter.format0("1234", "4111111111111112"));
    }
}
