package com.tallowbrook.payments.statements;

import org.apache.xml.security.Init;
import org.apache.xml.security.algorithms.MessageDigestAlgorithm;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.signature.XMLSignature;
import org.apache.xml.security.transforms.Transforms;
import org.springframework.stereotype.Component;
import org.w3c.dom.Document;

/**
 * Harbor Bank wants our monthly statements as XML with an enveloped signature over the whole
 * document, our certificate included in KeyInfo.
 */
@Component
public class BankStatementSigner {

    static {
        Init.init();
    }

    private final StatementSigningIdentity identity;

    public BankStatementSigner(StatementSigningIdentity identity) {
        this.identity = identity;
    }

    public Document sign(Document statement) throws XMLSecurityException {
        if (statement.getDocumentElement() == null) {
            throw new IllegalArgumentException("Empty statement document");
        }
        XMLSignature signature =
                new XMLSignature(statement, "", XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA256);
        statement.getDocumentElement().appendChild(signature.getElement());
        Transforms transforms = new Transforms(statement);
        transforms.addTransform(Transforms.TRANSFORM_ENVELOPED_SIGNATURE);
        transforms.addTransform(Transforms.TRANSFORM_C14N_EXCL_OMIT_COMMENTS);
        signature.addDocument("", transforms, MessageDigestAlgorithm.ALGO_ID_DIGEST_SHA256);
        signature.addKeyInfo(identity.chainHead());
        signature.sign(identity.key());
        return statement;
    }
}
