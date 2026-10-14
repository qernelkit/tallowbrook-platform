// Client-side field level encryption schema for tallowbrook.customers. The driver
// encrypts these fields before they leave the gateway; Mongo only sees ciphertext.
export const CUSTOMER_PII_KEY_ALT_NAME = 'customer-pii';

// Customs looks customers up by tax id, so that field needs equality matches.
const TAX_ID_FIELD = {
  encrypt: { bsonType: 'string', algorithm: 'AEAD_AES_256_CBC_HMAC_SHA_512-Deterministic' },
};
const DATE_OF_BIRTH_FIELD = {
  encrypt: { bsonType: 'date', algorithm: 'AEAD_AES_256_CBC_HMAC_SHA_512-Random' },
};
// The log redactor drops these paths from every record (see logger.js).
export const ENCRYPTED_FIELD_NAMES = ['taxId', 'dateOfBirth'];

/**
 * @param {import('mongodb').UUID} dataKeyId
 */
export function customerSchemaMap(dataKeyId) {
  return {
    'tallowbrook.customers': {
      bsonType: 'object',
      encryptMetadata: { keyId: [dataKeyId] },
      properties: {
        taxId: TAX_ID_FIELD,
        dateOfBirth: DATE_OF_BIRTH_FIELD,
      },
    },
  };
}
