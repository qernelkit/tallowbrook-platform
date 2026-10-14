// DPoP proofs (RFC 9449) for the session endpoint: each request that refreshes the
// session carries a proof signed by this browser's device key.
import { jsonToBase64Url, bytesToBase64Url, utf8 } from '../crypto/bytes';
import { deviceKey } from '../crypto/deviceKey';

export async function dpopProof(method: string, url: string): Promise<string> {
  const pair = await deviceKey();
  const jwk = await crypto.subtle.exportKey('jwk', pair.publicKey);
  const header = {
    typ: 'dpop+jwt',
    alg: 'ES256',
    jwk: { kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y },
  };
  const claims = {
    jti: crypto.randomUUID(),
    htm: method.toUpperCase(),
    htu: url.split('?')[0].split('#')[0],
    iat: Math.floor(Date.now() / 1000),
  };
  const signingInput = `${jsonToBase64Url(header)}.${jsonToBase64Url(claims)}`;
  const sig = await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, pair.privateKey, utf8(signingInput));
  return `${signingInput}.${bytesToBase64Url(new Uint8Array(sig))}`;
}
