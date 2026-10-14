'use strict';
// Harbor Pay settlement webhooks. Harbor Pay signs each delivery with its webhook key
// (rotated yearly; the current key is from their 2026 notice) and sends the signature
// base64-encoded in X-HarborPay-Signature.
const crypto = require('node:crypto');

const HARBOR_PAY_WEBHOOK_KEY =
  '-----BEGIN PUBLIC KEY-----\n' +
  'MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAlcWWnXQ6zqH54bTFbio0\n' +
  'bLdlaztz9r8z5NfJi1HWU1F1ueO64CRYw+FwD6LxD+0BqDNlDr35SwLK4+Estr5Y\n' +
  'N9XIrdX+Sj3NWRNAfa2gwegquZ3hF2Zszs087oRI3eiY1uBpBQiS99A/HM3QAcmd\n' +
  'iTjAMqoHMFM/m0L3MU6TIoX6xBwMAnHuCK8LiwSd9likAo+T3fhdLE/avBCGl4V7\n' +
  'UvGPkUiECpEta3xINc+Ac2S1fGJcyap/F2l9VilKfgJUl3OD3WifRx5ZZCVWPKBc\n' +
  'voL5EZTCK2+HvDXLDk6AUYYIZ0kesOoaxYB1zG/STiTBIqFo2HyHVt1C8J6HohbP\n' +
  'Qs+jc8m3oERAtk/JK78KdFkl9Wk99A/l0C9AjW32xeLgMNtB27iObD7Vs5ymYnCU\n' +
  'mWKaIb9kWhGsBh/sjqYyOxqbenZiSZzhMRXWFnkP09ESKrebAQgKC6ASFQ576bZB\n' +
  'T667AZyuK9oQ3AS0T8Qn1XFPSAjXQlqo+PFN4Ht5qyoG3v7ZsyLkp4tpnV7KL/Os\n' +
  'Ly2yCay3Pz44jc7qaZGNo3igUOYxNs2JzGfChmaEwrYpiAu+zE9Bwrfy6MWqPLzN\n' +
  'HwdKwKVwhvvigiwCwvuzL/9vD8VGDqip8wfaJH0RNhvenWFoIKMyUBM98527ybXT\n' +
  '1rDNP4saqFN14aFleOCwUyECAwEAAQ==\n' +
  '-----END PUBLIC KEY-----\n';

const SETTLEMENT_EVENTS = new Set(['settlement.completed', 'settlement.failed', 'payout.reversed']);

/**
 * @param {{ warn: Function, info: Function }} logger
 * @param {(event: any) => Promise<void>} apply
 * @returns {import('express').RequestHandler}
 */
function harborPayWebhook(logger, apply) {
  return async (req, res, next) => {
    try {
      const signatureHeader = req.get('x-harborpay-signature');
      if (signatureHeader === undefined) return res.status(401).end();
      const ok = crypto.verify(
        'sha256',
        req.body,
        { key: HARBOR_PAY_WEBHOOK_KEY, padding: crypto.constants.RSA_PKCS1_PSS_PADDING, saltLength: 32 },
        Buffer.from(signatureHeader, 'base64'),
      );
      if (!ok) {
        logger.warn({ partner: 'harbor-pay' }, 'partner webhook signature rejected');
        return res.status(401).end();
      }
      const event = JSON.parse(req.body.toString('utf8'));
      if (!SETTLEMENT_EVENTS.has(event.type)) {
        logger.info({ partner: 'harbor-pay', type: event.type }, 'ignoring partner event');
        return res.status(202).end();
      }
      await apply(event);
      return res.status(204).end();
    } catch (err) {
      return next(err);
    }
  };
}

module.exports = { harborPayWebhook };
