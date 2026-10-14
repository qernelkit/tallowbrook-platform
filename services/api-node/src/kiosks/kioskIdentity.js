// Depot kiosks (parcel lockers, self-service check-in) get an identity key when they
// are provisioned. The private half is written to the kiosk's secure element by the
// provisioning tool and is not kept here.
import { generateKeyPairSync } from 'node:crypto';

/** @typedef {{ id: string, depotCode: string, model: string }} Kiosk */

const DEPOT_CODE = /^[A-Z]{3}\d{2}$/;

/**
 * @param {Kiosk} kiosk
 */
export function provisionKioskIdentity(kiosk) {
  if (!DEPOT_CODE.test(kiosk.depotCode)) throw new Error(`bad depot code ${kiosk.depotCode}`);
  const { publicKey: identity, privateKey: forElement } = generateKeyPairSync('ed25519');
  return {
    kioskId: kiosk.id,
    depotCode: kiosk.depotCode,
    identity: identity.export({ type: 'spki', format: 'pem' }),
    forSecureElement: forElement.export({ type: 'pkcs8', format: 'der' }).toString('base64'),
    provisionedAt: new Date(),
  };
}
