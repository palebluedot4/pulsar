package oidc

import (
	"errors"
	"io"
	"mime"
	"net/http"
	"net/url"
)

// maxFormSize bounds the form-encoded body of a request.
const maxFormSize = 64 << 10

// errNotForm is returned by readParams for a POST whose body is not
// form-encoded.
var errNotForm = errors.New("the body is not application/x-www-form-urlencoded")

// readParams returns the parameters of a request: the form-encoded body of
// a POST, whose query is not read, or the query of any other. A parameter
// sent without a value is left out, as if it had not been sent (RFC 6749
// §3.1).
func readParams(w http.ResponseWriter, r *http.Request) (url.Values, error) {
	raw := r.URL.RawQuery
	if r.Method == http.MethodPost {
		mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
		if err != nil || mediaType != "application/x-www-form-urlencoded" {
			return nil, errNotForm
		}
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxFormSize))
		if err != nil {
			return nil, err
		}
		raw = string(body)
	}
	values, err := url.ParseQuery(raw)
	if err != nil {
		return nil, err
	}
	return nonEmpty(values), nil
}

// nonEmpty returns values without the parameters sent without a value, as
// if they had not been sent (RFC 6749 §3.1).
func nonEmpty(values url.Values) url.Values {
	params := make(url.Values, len(values))
	for name, vs := range values {
		for _, v := range vs {
			if v != "" {
				params[name] = append(params[name], v)
			}
		}
	}
	return params
}

// repeated returns the first of names that params holds more than once,
// which RFC 6749 §3.1 forbids.
func repeated(params url.Values, names []string) (string, bool) {
	for _, name := range names {
		if len(params[name]) > 1 {
			return name, true
		}
	}
	return "", false
}
