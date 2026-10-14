-- Turns on transparent data encryption for the billing database, protected by
-- the server certificate from server/V001.

CREATE DATABASE ENCRYPTION KEY
    WITH ALGORITHM = AES_256
    ENCRYPTION BY SERVER CERTIFICATE TdeProtector;
GO

ALTER DATABASE CURRENT SET ENCRYPTION ON;
GO
