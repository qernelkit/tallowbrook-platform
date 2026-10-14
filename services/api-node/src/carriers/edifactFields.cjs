'use strict';
// Consignee name and phone in IFTMIN messages for Kestrel Haulage. Their EDI gateway
// still expects these two segments encrypted with the key from the 2014 interchange
// agreement, hex-encoded inside the FTX free text.
const forge = require('node-forge');

const IV_BYTES = 8;

/**
 * @param {string} value
 * @param {Buffer} fieldKey 24-byte key from the interchange agreement
 * @returns {string} hex of IV followed by the encrypted field
 */
function encryptConsigneeField(value, fieldKey) {
  const iv = forge.random.getBytesSync(IV_BYTES);
  const block = forge.cipher.createCipher('3DES-CBC', forge.util.createBuffer(fieldKey.toString('binary')));
  block.start({ iv });
  block.update(forge.util.createBuffer(value, 'utf8'));
  if (!block.finish()) throw new Error('consignee field could not be padded');
  return forge.util.bytesToHex(iv + block.output.getBytes()).toUpperCase();
}

/**
 * EDIFACT release characters: ? escapes + : ' and itself.
 * @param {string} text
 */
function escapeEdifact(text) {
  return text.replace(/([?+:'])/g, '?$1');
}

module.exports = { encryptConsigneeField, escapeEdifact };
