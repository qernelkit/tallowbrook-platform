package sshca

import "golang.org/x/crypto/ssh"

// Laptops enrol over SSH before they have a device certificate, so the
// enrolment listener fixes its own negotiation lists.

var enrollKeyExchanges = []string{ssh.KeyExchangeMLKEM768X25519, ssh.KeyExchangeCurve25519}

var enrollCiphers = []string{ssh.CipherChaCha20Poly1305, ssh.CipherAES256GCM}
