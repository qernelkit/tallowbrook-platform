// Package kmsbootstrap lists the AWS keys the identity service owns.
// cmd/kms-bootstrap creates any that are missing.
package kmsbootstrap

import "github.com/aws/aws-sdk-go-v2/service/kms/types"

type plannedKey struct {
	Alias string
	Spec  types.KeySpec
	Usage types.KeyUsageType
}

var plannedKeys = []plannedKey{
	{Alias: "alias/identity-workforce-tokens", Spec: types.KeySpecEccNistP384, Usage: types.KeyUsageTypeSignVerify},
	{Alias: "alias/identity-attestations", Spec: types.KeySpecMlDsa65, Usage: types.KeyUsageTypeSignVerify},
	{Alias: "alias/identity-magic-links", Spec: types.KeySpecHmac256, Usage: types.KeyUsageTypeGenerateVerifyMac},
}

// Key is one key to create.
type Key struct {
	Alias string
	Spec  types.KeySpec
	Usage types.KeyUsageType
}

// Keys returns the planned keys.
func Keys() []Key {
	out := make([]Key, 0, len(plannedKeys))
	for _, k := range plannedKeys {
		out = append(out, Key(k))
	}
	return out
}
