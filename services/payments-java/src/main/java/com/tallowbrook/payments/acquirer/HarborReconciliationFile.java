package com.tallowbrook.payments.acquirer;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.List;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;

/** The nightly reconciliation download from Harbor Bank. The first line is a column header. */
@Component
public class HarborReconciliationFile {

    private static final Logger log = LoggerFactory.getLogger(HarborReconciliationFile.class);

    public List<ReconciliationLine> read(byte[] download, SecretKey harborKey)
            throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, harborKey);
        String text = new String(cipher.doFinal(download), StandardCharsets.US_ASCII);
        List<ReconciliationLine> lines =
                text.lines()
                        .skip(1)
                        .filter(line -> !line.isBlank())
                        .map(ReconciliationLine::parse)
                        .toList();
        log.info("Reconciliation file with {} lines", lines.size());
        return lines;
    }
}
