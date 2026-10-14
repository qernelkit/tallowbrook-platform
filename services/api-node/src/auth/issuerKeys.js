// Verification half of the access-token key. The edge workers bundle this module so
// they can check tokens without a round trip to the gateway.
export const ACCESS_TOKEN_PUBLIC_KEY = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEQKomyBVpBNpmoaISQ8Cu2ZbQRyv5
dRaF1lQZvjYI6/jb0HlcAO1n5Zp1VchZMKdzA3GYtzjiuKersi0RmnY6Uw==
-----END PUBLIC KEY-----`;

export const ACCESS_KEY_ID = 'tb-access-2026-03';
