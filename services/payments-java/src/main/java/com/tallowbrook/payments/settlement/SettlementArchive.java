package com.tallowbrook.payments.settlement;

import net.lingala.zip4j.ZipFile;
import net.lingala.zip4j.model.ZipParameters;
import net.lingala.zip4j.model.enums.AesKeyStrength;
import net.lingala.zip4j.model.enums.CompressionLevel;
import net.lingala.zip4j.model.enums.EncryptionMethod;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

/**
 * Daily report archives. Small merchants open theirs with the operating system's built-in unzip,
 * which only understands the original ZIP password scheme; the banks take WinZip AES archives.
 */
@Component
public class SettlementArchive {

    private static final Logger log = LoggerFactory.getLogger(SettlementArchive.class);

    public Path forMerchant(String merchantId, List<Path> reports, char[] password, Path outDir)
            throws IOException {
        ZipParameters merchantParams = new ZipParameters();
        merchantParams.setCompressionLevel(CompressionLevel.NORMAL);
        merchantParams.setEncryptFiles(true);
        merchantParams.setEncryptionMethod(EncryptionMethod.ZIP_STANDARD);
        return write(
                outDir.resolve(merchantId + "-reports.zip"), reports, merchantParams, password);
    }

    public Path forBank(String bankCode, List<Path> reports, char[] password, Path outDir)
            throws IOException {
        ZipParameters bankParams = new ZipParameters();
        bankParams.setCompressionLevel(CompressionLevel.MAXIMUM);
        bankParams.setEncryptFiles(true);
        bankParams.setEncryptionMethod(EncryptionMethod.AES);
        bankParams.setAesKeyStrength(AesKeyStrength.KEY_STRENGTH_256);
        return write(outDir.resolve(bankCode + "-settlement.zip"), reports, bankParams, password);
    }

    private static Path write(
            Path target, List<Path> reports, ZipParameters params, char[] password)
            throws IOException {
        Files.deleteIfExists(target);
        try (ZipFile zip = new ZipFile(target.toFile(), password)) {
            zip.addFiles(reports.stream().map(Path::toFile).toList(), params);
        }
        log.info("Wrote {} with {} report(s)", target.getFileName(), reports.size());
        return target;
    }
}
