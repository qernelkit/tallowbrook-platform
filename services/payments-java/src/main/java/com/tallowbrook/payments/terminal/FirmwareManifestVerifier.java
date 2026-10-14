package com.tallowbrook.payments.terminal;

import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.params.SLHDSAParameters;
import org.bouncycastle.crypto.params.SLHDSAPublicKeyParameters;
import org.bouncycastle.crypto.signers.SLHDSASigner;
import org.bouncycastle.pqc.crypto.xmss.XMSSParameters;
import org.bouncycastle.pqc.crypto.xmss.XMSSPublicKeyParameters;
import org.bouncycastle.pqc.crypto.xmss.XMSSSigner;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

/**
 * Checks reader firmware manifests before a depot is allowed to roll them out. The two reader
 * vendors sign their manifests differently; each vendor's key comes from its onboarding pack.
 */
@Component
public class FirmwareManifestVerifier {

    private static final Logger log = LoggerFactory.getLogger(FirmwareManifestVerifier.class);

    public enum Vendor {
        ARDEN,
        BRIGHTWATER
    }

    public boolean verify(Vendor vendor, byte[] manifest, byte[] signature, byte[] vendorKey) {
        boolean ok =
                switch (vendor) {
                    case ARDEN -> verifyArden(manifest, signature, vendorKey);
                    case BRIGHTWATER -> verifyBrightwater(manifest, signature, vendorKey);
                };
        if (!ok) {
            log.warn("Firmware manifest from {} rejected", vendor);
        }
        return ok;
    }

    private boolean verifyArden(byte[] manifest, byte[] signature, byte[] vendorKey) {
        XMSSParameters params = new XMSSParameters(10, new SHA256Digest());
        XMSSPublicKeyParameters key =
                new XMSSPublicKeyParameters.Builder(params).withPublicKey(vendorKey).build();
        XMSSSigner verifier = new XMSSSigner();
        verifier.init(false, key);
        return verifier.verifySignature(manifest, signature);
    }

    private boolean verifyBrightwater(byte[] manifest, byte[] signature, byte[] vendorKey) {
        SLHDSAPublicKeyParameters key =
                new SLHDSAPublicKeyParameters(SLHDSAParameters.sha2_128s, vendorKey);
        SLHDSASigner verifier = new SLHDSASigner();
        verifier.init(false, key);
        return verifier.verifySignature(manifest, signature);
    }
}
