package com.tallowbrook.payments.webhook;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.util.HexFormat;
import java.util.Locale;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * Settlement callbacks from the acquirers carry a hex MAC of the body in {@code X-Callback-Mac}.
 */
@Component
public class AcquirerCallbackVerifier {

    private static final Logger log = LoggerFactory.getLogger(AcquirerCallbackVerifier.class);

    public boolean verify(
            AcquirerMacAlgorithm acquirer, byte[] callbackSecret, byte[] body, String macHex)
            throws GeneralSecurityException {
        if (macHex == null || macHex.length() % 2 != 0) {
            log.warn("Malformed callback header from {}", acquirer.name().toLowerCase(Locale.ROOT));
            return false;
        }
        Mac mac = Mac.getInstance(acquirer.macName());
        mac.init(new SecretKeySpec(callbackSecret, acquirer.macName()));
        byte[] expected = mac.doFinal(body);
        return MessageDigest.isEqual(expected, HexFormat.of().parseHex(macHex));
    }
}
