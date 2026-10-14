package oidc

import (
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"net/http"
)

type providerMetadata struct {
	Issuer                            string   `json:"issuer"`
	AuthorizationEndpoint             string   `json:"authorization_endpoint"`
	TokenEndpoint                     string   `json:"token_endpoint"`
	UserinfoEndpoint                  string   `json:"userinfo_endpoint"`
	KeySetURI                         string   `json:"jwks_uri"`
	ResponseTypesSupported            []string `json:"response_types_supported"`
	SubjectTypesSupported             []string `json:"subject_types_supported"`
	ScopesSupported                   []string `json:"scopes_supported"`
	IDTokenSigningAlgValuesSupported  []string `json:"id_token_signing_alg_values_supported"`
	CodeChallengeMethodsSupported     []string `json:"code_challenge_methods_supported"`
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported"`
	BackchannelLogoutSupported        bool     `json:"backchannel_logout_supported"`
	BackchannelLogoutSessionSupported bool     `json:"backchannel_logout_session_supported"`
}

// Discovery serves /.well-known/openid-configuration.
type Discovery struct {
	body []byte
	etag string
}

// NewDiscovery builds the metadata document. tokenBase is the address of the
// token endpoint, which listens separately from the browser-facing endpoints.
func NewDiscovery(issuer, tokenBase string) (*Discovery, error) {
	md := providerMetadata{
		Issuer:                            issuer,
		AuthorizationEndpoint:             issuer + "/authorize",
		TokenEndpoint:                     tokenBase + "/token",
		UserinfoEndpoint:                  issuer + "/userinfo",
		KeySetURI:                         issuer + "/jwks.json",
		ResponseTypesSupported:            []string{"code"},
		SubjectTypesSupported:             []string{"public"},
		ScopesSupported:                   supportedScopes,
		IDTokenSigningAlgValuesSupported:  idTokenAlgValues,
		CodeChallengeMethodsSupported:     []string{"S256"},
		TokenEndpointAuthMethodsSupported: []string{"none", "tls_client_auth"},
		BackchannelLogoutSupported:        true,
		BackchannelLogoutSessionSupported: true,
	}
	body, err := json.Marshal(md)
	if err != nil {
		return nil, err
	}
	return &Discovery{body: body, etag: etagFor(body)}, nil
}

func (d *Discovery) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	serveCached(w, r, d.body, d.etag, "public, max-age=300")
}

// etagFor is the strong ETag of a cached JSON document.
func etagFor(body []byte) string {
	sum := md5.Sum(body)
	return `"` + hex.EncodeToString(sum[:]) + `"`
}

func serveCached(w http.ResponseWriter, r *http.Request, body []byte, etag, cacheControl string) {
	w.Header().Set("ETag", etag)
	w.Header().Set("Cache-Control", cacheControl)
	if r.Header.Get("If-None-Match") == etag {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(body)
}
