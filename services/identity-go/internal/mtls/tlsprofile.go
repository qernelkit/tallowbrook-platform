package mtls

import "crypto/tls"

// Negotiation settings for the token endpoint. Only ECDSA server
// certificates are deployed there.

var tokenEndpointGroups = []tls.CurveID{tls.X25519MLKEM768, tls.SecP256r1MLKEM768, tls.X25519, tls.CurveP256}

var tokenEndpointSuites = []uint16{
	tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
}
