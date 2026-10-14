package com.tallowbrook.payments.settlement;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.LocalDate;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.stream.Collectors;

/** Builds the header record of a Harbor Bank settlement file. Fields are keyed by their number. */
final class BankFileHeader {

    String build(
            String bankCode,
            LocalDate businessDate,
            int recordCount,
            long totalMinorUnits,
            byte[] body)
            throws NoSuchAlgorithmException {
        if (recordCount <= 0) {
            throw new IllegalArgumentException("A settlement file needs at least one record");
        }
        Map<String, String> header = new LinkedHashMap<>();
        header.put("01", BankFileFormat.HEADER_RECORD_TYPE);
        header.put("02", bankCode);
        header.put("03", BankFileFormat.HEADER_DATE.format(businessDate));
        header.put("04", Integer.toString(recordCount));
        header.put("05", Long.toString(totalMinorUnits));
        MessageDigest md = MessageDigest.getInstance(BankFileFormat.HEADER_DIGEST);
        byte[] bodyHash = md.digest(body);
        header.put("06", HexFormat.of().withUpperCase().formatHex(bodyHash));
        header.put("07", BankFileFormat.FORMAT_VERSION);
        return header.values().stream()
                .collect(Collectors.joining(String.valueOf(BankFileFormat.FIELD_SEPARATOR)));
    }
}
