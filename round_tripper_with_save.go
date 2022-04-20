package oauthproxy

import (
	"bytes"
	"io"
	"io/ioutil"
	"net/http"
)

type RoundTripperWithSave struct {
	rtp http.RoundTripper
	// req  *http.Request
	// resp *http.Response
	responseBody io.Reader
}

func NewRoundTripperWithSave(rtp http.RoundTripper) *RoundTripperWithSave {
	return &RoundTripperWithSave{rtp: rtp}
}

func (rt *RoundTripperWithSave) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := rt.rtp.RoundTrip(req)
	if err != nil {
		return resp, err
	}

	b, err := ioutil.ReadAll(resp.Body)
	resp.Body = ioutil.NopCloser(bytes.NewBuffer(b))
	rt.responseBody = ioutil.NopCloser(bytes.NewBuffer(b))
	return resp, err
}

// func (rt *RoundTripperWithSave) LastRequest() *http.Request {
// 	return rt.req
// }

// func (rt *RoundTripperWithSave) LastResponse() *http.Response {
// 	return rt.resp
// }

func (rt *RoundTripperWithSave) LastResponseBody() io.Reader {
	return rt.responseBody
}
