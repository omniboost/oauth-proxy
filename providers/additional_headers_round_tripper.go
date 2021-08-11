package providers

import (
	"net/http"
)

type AdditionalHeadersRoundTripper struct {
	rtp     http.RoundTripper
	Headers map[string]string
	// req  *http.Request
	// resp *http.Response
}

func NewAdditionalHeadersRoundTripper(rtp http.RoundTripper) *AdditionalHeadersRoundTripper {
	return &AdditionalHeadersRoundTripper{rtp: rtp}
}

func (rt *AdditionalHeadersRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	// Modify the request
	// - add additional headers
	for k, v := range rt.Headers {
		req.Header.Add(k, v)
	}

	return rt.rtp.RoundTrip(req)
}
