-- Server-level objects for transparent data encryption on the billing
-- instance. Run against master with sqlcmd:
--   sqlcmd -S billing-sql -d master -i V001__tde_prerequisites.sql \
--     -v TdeMasterKeyPassword=... TdeBackupPassword=...
USE master;
GO

CREATE MASTER KEY ENCRYPTION BY PASSWORD = '$(TdeMasterKeyPassword)';
GO

CREATE CERTIFICATE TdeProtector WITH SUBJECT = 'Billing TDE protector';
GO

-- Without this backup a restored billing database cannot be opened anywhere else.
BACKUP CERTIFICATE TdeProtector
    TO FILE = '/var/opt/mssql/backup/tde-protector.cer'
    WITH PRIVATE KEY (
        FILE = '/var/opt/mssql/backup/tde-protector.pvk',
        ENCRYPTION BY PASSWORD = '$(TdeBackupPassword)'
    );
GO
