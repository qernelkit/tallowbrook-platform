// Outbound webhook contract, as documented in openapi/gateway.json.
export const SIGNATURE_HEADER = 'X-Tallowbrook-Signature';
export const EVENT_HEADER = 'X-Tallowbrook-Event';
export const DELIVERY_HEADER = 'X-Tallowbrook-Delivery';
export const WEBHOOK_HMAC_DIGEST = 'sha512';
export const RETRY_DELAYS_SECONDS = [10, 60, 300, 1800, 7200, 21600, 43200, 86400];
