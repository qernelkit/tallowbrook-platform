// Package httpx holds the HTTP plumbing shared by the identity binaries:
// JSON problem responses, request IDs, logging, rate limits and recovery.
package httpx

import (
	"encoding/json"
	"errors"
	"net/http"
)

// Problem is an RFC 9457 problem document.
type Problem struct {
	Type      string `json:"type,omitempty"`
	Title     string `json:"title"`
	Status    int    `json:"status"`
	Detail    string `json:"detail,omitempty"`
	RequestID string `json:"request_id,omitempty"`
}

// Error is an error that knows its HTTP status.
type Error struct {
	Status int
	Title  string
	Detail string
}

func (e *Error) Error() string { return e.Title + ": " + e.Detail }

// Common errors.
var (
	ErrBadRequest   = &Error{Status: http.StatusBadRequest, Title: "Bad request"}
	ErrUnauthorized = &Error{Status: http.StatusUnauthorized, Title: "Sign-in required"}
	ErrForbidden    = &Error{Status: http.StatusForbidden, Title: "Not allowed"}
	ErrNotFound     = &Error{Status: http.StatusNotFound, Title: "Not found"}
	ErrConflict     = &Error{Status: http.StatusConflict, Title: "Conflict"}
	ErrTooMany      = &Error{Status: http.StatusTooManyRequests, Title: "Too many requests"}
)

// BadRequest returns a 400 with detail.
func BadRequest(detail string) *Error {
	return &Error{Status: http.StatusBadRequest, Title: "Bad request", Detail: detail}
}

// WriteError writes err as a problem document. Errors that are not *Error
// become a 500 without detail, so internals never reach the client.
func WriteError(w http.ResponseWriter, r *http.Request, err error) {
	var he *Error
	if !errors.As(err, &he) {
		he = &Error{Status: http.StatusInternalServerError, Title: "Internal error"}
		LoggerFrom(r.Context()).Error("unhandled error", "err", err)
	}
	p := Problem{Title: he.Title, Status: he.Status, Detail: he.Detail, RequestID: RequestID(r.Context())}
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(he.Status)
	_ = json.NewEncoder(w).Encode(p)
}

// WriteJSON writes v with status.
func WriteJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// DecodeJSON reads a JSON body of at most limit bytes into v, rejecting
// unknown fields.
func DecodeJSON(r *http.Request, limit int64, v any) error {
	dec := json.NewDecoder(http.MaxBytesReader(nil, r.Body, limit))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return BadRequest("request body is not valid JSON for this endpoint")
	}
	return nil
}
