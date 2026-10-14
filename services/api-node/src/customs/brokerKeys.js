// One-off: creates the OpenPGP key for the customs desk mailbox, which receives
// encrypted queries from brokers. Run from the admin console, never on a schedule.
import { generateKey } from 'openpgp';
import { secret } from '../config.js';
import { collection } from '../db/collections.js';

const CUSTOMS_DESK_UID = { name: 'Tallowbrook Customs Desk', email: 'customs-desk@tallowbrook.example' };

/**
 * @param {import('mongodb').Db} db
 * @returns {Promise<string>} the armored public half, for the broker portal
 */
export async function createCustomsDeskKey(db) {
  const existing = await collection(db, 'mailboxKeys').findOne({ mailbox: 'customs-desk', retiredAt: null });
  if (existing) throw new Error('customs desk already has an active key; retire it first');
  const deskPassword = secret('CUSTOMS_DESK_PASSWORD');
  const { privateKey: armoredPrivate, publicKey: armoredPublic } = await generateKey({
    userIDs: [CUSTOMS_DESK_UID],
    passphrase: deskPassword,
  });
  await collection(db, 'mailboxKeys').insertOne({
    mailbox: 'customs-desk',
    armoredPublic,
    armoredPrivate,
    createdAt: new Date(),
    retiredAt: null,
  });
  return armoredPublic;
}
