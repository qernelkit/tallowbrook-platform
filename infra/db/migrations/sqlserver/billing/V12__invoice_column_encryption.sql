-- Invoice table with the IBAN sealed under a column key, a lookup hash for
-- payment matching, and fingerprints used to reject duplicate PDF uploads.

CREATE ASYMMETRIC KEY BillingColumnKek
    WITH ALGORITHM = RSA_3072
    ENCRYPTION BY PASSWORD = '$(ColumnKekPassword)';
GO

CREATE SYMMETRIC KEY BillingColumnKey
    WITH ALGORITHM = AES_256
    ENCRYPTION BY ASYMMETRIC KEY BillingColumnKek;
GO

CREATE TABLE dbo.Invoices (
    invoice_id bigint IDENTITY(1, 1) NOT NULL PRIMARY KEY,
    invoice_no varchar(20) NOT NULL UNIQUE,
    customer_id int NOT NULL,
    total_minor bigint NOT NULL,
    currency char(3) NOT NULL,
    iban_plain_staging varchar(34) NULL,
    iban_sealed varbinary(256) NULL,
    pdf_blob varbinary(max) NOT NULL,
    iban_lookup AS CONVERT(binary(32), HASHBYTES('SHA2_256', UPPER(iban_plain_staging))) PERSISTED,
    pdf_fingerprint AS HASHBYTES('MD5', pdf_blob) PERSISTED,
    row_checksum AS CHECKSUM(invoice_no, customer_id, total_minor),
    issued_at datetime2 NOT NULL DEFAULT SYSUTCDATETIME()
);
GO

CREATE INDEX IX_Invoices_IbanLookup ON dbo.Invoices (iban_lookup);
CREATE INDEX IX_Invoices_PdfFingerprint ON dbo.Invoices (pdf_fingerprint);
GO

CREATE PROCEDURE dbo.SealInvoiceIban
    @invoice_id bigint
AS
BEGIN
    SET NOCOUNT ON;
    OPEN SYMMETRIC KEY BillingColumnKey
        DECRYPTION BY ASYMMETRIC KEY BillingColumnKek WITH PASSWORD = '$(ColumnKekPassword)';
    UPDATE dbo.Invoices
    SET iban_sealed = ENCRYPTBYKEY(KEY_GUID('BillingColumnKey'), iban_plain_staging)
    WHERE invoice_id = @invoice_id;
    CLOSE SYMMETRIC KEY BillingColumnKey;
END;
GO
