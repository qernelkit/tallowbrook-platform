// Per-carrier settings used by the nightly manifest export and the EDI bridge.

/**
 * @typedef {object} CarrierProfile
 * @property {string} displayName
 * @property {'csv' | 'json' | 'edifact'} manifestFormat
 * @property {string | null} sftpHost
 * @property {string[]} columns
 * @property {string} cutoffUtc
 * @property {string} [exportCipher]
 * @property {string} [exportIvHex]
 */

/** @type {Record<string, CarrierProfile>} */
export const CARRIER_PROFILES = {
  'atlas-freight': {
    displayName: 'Atlas Freight',
    manifestFormat: 'csv',
    sftpHost: 'sftp.atlasfreight.example',
    columns: ['consignment', 'pieces', 'weightKg', 'postcode', 'country', 'service'],
    cutoffUtc: '22:00',
    // Atlas Freight's import tool reads CBC exports only, with the IV agreed at onboarding.
    exportCipher: 'aes-128-cbc',
    exportIvHex: 'c7a8a4d8fb6225c7912f971d3eda8fc4',
  },
  'ridgeway-parcel': {
    displayName: 'Ridgeway Parcel',
    manifestFormat: 'json',
    sftpHost: null,
    columns: ['consignment', 'pieces', 'weightKg', 'postcode', 'country'],
    cutoffUtc: '20:30',
  },
  'kestrel-haulage': {
    displayName: 'Kestrel Haulage',
    manifestFormat: 'edifact',
    sftpHost: 'edi.kestrelhaulage.example',
    columns: [],
    cutoffUtc: '23:15',
  },
};

/**
 * @param {string} carrierId
 * @returns {CarrierProfile}
 */
export function carrierProfile(carrierId) {
  const profile = CARRIER_PROFILES[carrierId];
  if (!profile) throw new Error(`unknown carrier ${carrierId}`);
  return profile;
}

/**
 * @param {string} carrierId
 * @param {Date} now
 */
export function pastCutoff(carrierId, now) {
  const [hours, minutes] = carrierProfile(carrierId).cutoffUtc.split(':').map(Number);
  return now.getUTCHours() * 60 + now.getUTCMinutes() >= hours * 60 + minutes;
}
