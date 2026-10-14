package com.tallowbrook.payments.statements;

import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.security.cert.CertificateEncodingException;
import java.util.List;

/**
 * Remittance advice for merchants that reconcile in their ERP: a CMS SignedData with the advice
 * encapsulated, so the ERP can check it came from us before booking it.
 */
@Component
public class RemittanceCmsSigner {

    private final StatementSigningIdentity identity;

    public RemittanceCmsSigner(StatementSigningIdentity identity) {
        this.identity = identity;
    }

    public byte[] sign(byte[] advice)
            throws OperatorCreationException,
                    CMSException,
                    CertificateEncodingException,
                    IOException {
        CMSSignedDataGenerator generator = new CMSSignedDataGenerator();
        ContentSigner contentSigner =
                new JcaContentSignerBuilder("SHA256withRSA").build(identity.key());
        generator.addSignerInfoGenerator(
                new JcaSignerInfoGeneratorBuilder(new JcaDigestCalculatorProviderBuilder().build())
                        .build(contentSigner, identity.chainHead()));
        generator.addCertificates(new JcaCertStore(List.of(identity.chainHead())));
        CMSSignedData signed = generator.generate(new CMSProcessableByteArray(advice), true);
        return signed.getEncoded();
    }
}
