'use strict';
// Kestrel's drivers carry iOS handhelds that enrol with a PKCS#12 bundle holding the
// device key and its chain. The bundle is produced from the device record issued by
// the provisioning service.
const forge = require('node-forge');

/**
 * @typedef {object} HandheldDevice
 * @property {string} serial
 * @property {string} keyPem device key issued by provisioning
 * @property {string[]} chainPem leaf first
 */

/**
 * @param {HandheldDevice} device
 * @param {string} bundlePassword shown once to the depot supervisor
 * @returns {Buffer}
 */
function buildHandheldBundle(device, bundlePassword) {
  if (!/^[A-Z0-9]{10,14}$/.test(device.serial)) throw new Error('unexpected handheld serial');
  if (device.chainPem.length === 0) throw new Error('handheld record has no chain');
  const deviceKey = forge.pki.privateKeyFromPem(device.keyPem);
  const chain = device.chainPem.map((pem) => forge.pki.certificateFromPem(pem));
  // iOS imports these only when they use the older PBE scheme (see the forge README).
  const asn1 = forge.pkcs12.toPkcs12Asn1(deviceKey, chain, bundlePassword, {
    algorithm: '3des',
    friendlyName: `Kestrel handheld ${device.serial}`,
  });
  return Buffer.from(forge.asn1.toDer(asn1).getBytes(), 'binary');
}

/**
 * @param {string} serial
 */
function bundleFileName(serial) {
  return `kestrel-${serial.toLowerCase()}.p12`;
}

module.exports = { buildHandheldBundle, bundleFileName };
