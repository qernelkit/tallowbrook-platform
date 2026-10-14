package oidc

import (
	"context"
	"crypto/sha512"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"slices"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
)

// SignAPI is the part of the AWS client the workforce signer uses.
type SignAPI interface {
	Sign(ctx context.Context, in *kms.SignInput, optFns ...func(*kms.Options)) (*kms.SignOutput, error)
}

// WorkforceSigner signs workforce-realm ID tokens with a key that never
// leaves AWS. Employees' tokens are accepted by internal tools that pin this
// issuer's key ID.
type WorkforceSigner struct {
	api   SignAPI
	keyID string
	alg   string
	kid   string
}

// NewWorkforceSigner checks alg against the values the SDK knows.
func NewWorkforceSigner(api SignAPI, keyID, alg, kid string) (*WorkforceSigner, error) {
	if !slices.Contains(types.SigningAlgorithmSpec("").Values(), types.SigningAlgorithmSpec(alg)) {
		return nil, fmt.Errorf("oidc: unknown signing algorithm %q", alg)
	}
	return &WorkforceSigner{api: api, keyID: keyID, alg: alg, kid: kid}, nil
}

var seg = base64.RawURLEncoding

// Sign returns a compact JWS over claims.
func (s *WorkforceSigner) Sign(ctx context.Context, claims map[string]any) (string, error) {
	header := []byte(`{"alg":"ES384","typ":"JWT","kid":"` + s.kid + `"}`)
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	signingInput := seg.EncodeToString(header) + "." + seg.EncodeToString(payload)
	digest := sha512.Sum384([]byte(signingInput))
	out, err := s.api.Sign(ctx, &kms.SignInput{
		KeyId:            aws.String(s.keyID),
		Message:          digest[:],
		MessageType:      types.MessageTypeDigest,
		SigningAlgorithm: types.SigningAlgorithmSpec(s.alg),
	})
	if err != nil {
		return "", fmt.Errorf("oidc: workforce token: %w", err)
	}
	sig, err := fixedWidth(out.Signature, 48)
	if err != nil {
		return "", err
	}
	return signingInput + "." + seg.EncodeToString(sig), nil
}

// fixedWidth converts the DER (r, s) pair AWS returns into the r||s form JWS
// expects, each half left-padded to size bytes.
func fixedWidth(der []byte, size int) ([]byte, error) {
	var rs struct{ R, S *big.Int }
	rest, err := asn1.Unmarshal(der, &rs)
	if err != nil || len(rest) != 0 {
		return nil, errors.New("oidc: malformed signature from AWS")
	}
	out := make([]byte, 2*size)
	rs.R.FillBytes(out[:size])
	rs.S.FillBytes(out[size:])
	return out, nil
}
