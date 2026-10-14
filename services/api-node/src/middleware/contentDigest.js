// RFC 9530 Content-Digest for outbound webhook payloads, so receivers can check the
// body independently of the signature header.
import { webcrypto } from 'node:crypto';

const CONTENT_DIGEST_ALGORITHM = 'SHA-512';

/**
 * @param {Buffer} body
 * @returns {Promise<string>} the header value, e.g. sha-512=:…:
 */
export async function contentDigest(body) {
  const hash = await webcrypto.subtle.digest(CONTENT_DIGEST_ALGORITHM, body);
  const b64 = Buffer.from(hash).toString('base64');
  return `${CONTENT_DIGEST_ALGORITHM.toLowerCase()}=:${b64}:`;
}
