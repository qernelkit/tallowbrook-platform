package com.tallowbrook.payments.settlement;

import java.time.format.DateTimeFormatter;

/** Harbor Bank settlement file layout, header record (bank specification v3.2, section 3). */
final class BankFileFormat {

    static final String HEADER_RECORD_TYPE = "01";
    static final String FORMAT_VERSION = "0302";
    static final char FIELD_SEPARATOR = '|';
    static final DateTimeFormatter HEADER_DATE = DateTimeFormatter.ofPattern("yyyyMMdd");

    /** Field 06 of the header carries a fingerprint of the file body, upper-case hex. */
    static final String HEADER_DIGEST = "SHA-1";

    private BankFileFormat() {}
}
