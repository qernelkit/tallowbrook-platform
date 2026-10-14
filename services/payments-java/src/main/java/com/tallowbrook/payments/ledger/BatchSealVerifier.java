package com.tallowbrook.payments.ledger;

import com.tallowbrook.payments.config.PaymentsProperties;

import org.bouncycastle.crypto.params.MLDSAParameters;
import org.bouncycastle.crypto.params.MLDSAPublicKeyParameters;
import org.bouncycastle.crypto.signers.MLDSASigner;
import org.springframework.stereotype.Component;

import java.util.Base64;

/**
 * The ledger service seals each journal batch it accepts; we check the seal before marking a payout
 * settled.
 */
@Component
public class BatchSealVerifier {

    private final byte[] ledgerKey;

    public BatchSealVerifier(PaymentsProperties properties) {
        this.ledgerKey = Base64.getDecoder().decode(properties.ledger().sealPublicKey());
    }

    public boolean verify(byte[] batch, byte[] seal) {
        MLDSAPublicKeyParameters key =
                new MLDSAPublicKeyParameters(MLDSAParameters.ml_dsa_65, ledgerKey);
        MLDSASigner verifier = new MLDSASigner();
        verifier.init(false, key);
        verifier.update(batch, 0, batch.length);
        return verifier.verifySignature(seal);
    }
}
