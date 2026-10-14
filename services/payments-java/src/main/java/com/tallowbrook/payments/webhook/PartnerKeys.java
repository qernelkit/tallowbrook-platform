package com.tallowbrook.payments.webhook;

import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.stream.Collectors;

/**
 * Public key our delivery partner signs its webhooks with, from their onboarding pack (March 2025).
 */
public final class PartnerKeys {

    private static final String PARTNER_WEBHOOK_KEY =
            """
            -----BEGIN PUBLIC KEY-----
            MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAlcWWnXQ6zqH54bTFbio0
            bLdlaztz9r8z5NfJi1HWU1F1ueO64CRYw+FwD6LxD+0BqDNlDr35SwLK4+Estr5Y
            N9XIrdX+Sj3NWRNAfa2gwegquZ3hF2Zszs087oRI3eiY1uBpBQiS99A/HM3QAcmd
            iTjAMqoHMFM/m0L3MU6TIoX6xBwMAnHuCK8LiwSd9likAo+T3fhdLE/avBCGl4V7
            UvGPkUiECpEta3xINc+Ac2S1fGJcyap/F2l9VilKfgJUl3OD3WifRx5ZZCVWPKBc
            voL5EZTCK2+HvDXLDk6AUYYIZ0kesOoaxYB1zG/STiTBIqFo2HyHVt1C8J6HohbP
            Qs+jc8m3oERAtk/JK78KdFkl9Wk99A/l0C9AjW32xeLgMNtB27iObD7Vs5ymYnCU
            mWKaIb9kWhGsBh/sjqYyOxqbenZiSZzhMRXWFnkP09ESKrebAQgKC6ASFQ576bZB
            T667AZyuK9oQ3AS0T8Qn1XFPSAjXQlqo+PFN4Ht5qyoG3v7ZsyLkp4tpnV7KL/Os
            Ly2yCay3Pz44jc7qaZGNo3igUOYxNs2JzGfChmaEwrYpiAu+zE9Bwrfy6MWqPLzN
            HwdKwKVwhvvigiwCwvuzL/9vD8VGDqip8wfaJH0RNhvenWFoIKMyUBM98527ybXT
            1rDNP4saqFN14aFleOCwUyECAwEAAQ==
            -----END PUBLIC KEY-----
            """;

    private PartnerKeys() {}

    public static PublicKey partnerWebhookKey() throws GeneralSecurityException {
        String body =
                PARTNER_WEBHOOK_KEY
                        .lines()
                        .filter(line -> !line.startsWith("-----"))
                        .collect(Collectors.joining());
        byte[] der = Base64.getDecoder().decode(body);
        return KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(der));
    }
}
