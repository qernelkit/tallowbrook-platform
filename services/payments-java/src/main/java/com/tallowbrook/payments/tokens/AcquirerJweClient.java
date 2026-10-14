package com.tallowbrook.payments.tokens;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.RSAEncrypter;
import com.nimbusds.jose.crypto.RSASSAVerifier;

import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;

/**
 * The Northgate acquirer API: requests go as JWEs to the acquirer's encryption key, responses come
 * back as JWSs signed with the acquirer's signing key. Both keys come from the acquirer's JWK set.
 */
public class AcquirerJweClient {

    private final RSAPublicKey requestKey;
    private final String requestKeyId;
    private final RSAPublicKey responseKey;

    public AcquirerJweClient(
            RSAPublicKey requestKey, String requestKeyId, RSAPublicKey responseKey) {
        this.requestKey = requestKey;
        this.requestKeyId = requestKeyId;
        this.responseKey = responseKey;
    }

    public String sealRequest(String json) throws JOSEException {
        JWEHeader header =
                new JWEHeader.Builder(
                                JWEAlgorithm.RSA_OAEP_256, // key management
                                EncryptionMethod.A256GCM) // content encryption
                        .keyID(requestKeyId)
                        .type(JOSEObjectType.JOSE)
                        .build();
        JWEObject request = new JWEObject(header, new Payload(json));
        request.encrypt(new RSAEncrypter(requestKey));
        return request.serialize();
    }

    public String readResponse(String compact) throws ParseException, JOSEException {
        JWSObject response = JWSObject.parse(compact);
        if (!JWSAlgorithm.PS256.equals(response.getHeader().getAlgorithm())) {
            throw new AcquirerResponseException(
                    "Unexpected response signature algorithm "
                            + response.getHeader().getAlgorithm());
        }
        if (!response.verify(new RSASSAVerifier(responseKey))) {
            throw new AcquirerResponseException("Acquirer response signature did not verify");
        }
        return response.getPayload().toString();
    }

    public static class AcquirerResponseException extends RuntimeException {

        public AcquirerResponseException(String message) {
            super(message);
        }
    }
}
