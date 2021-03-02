package providers

import (
	"bytes"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"net/url"
)

type JSONTokenExchangeRoundTripper struct {
	rtp http.RoundTripper
	// req  *http.Request
	// resp *http.Response
}

func NewJSONTokenExchangeRoundTripper(rtp http.RoundTripper) *JSONTokenExchangeRoundTripper {
	return &JSONTokenExchangeRoundTripper{rtp: rtp}
}

func (rt *JSONTokenExchangeRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	// Modify the request
	// - parse the body and convert to json notation
	// - Set Content-Type to application/json
	err := req.ParseForm()
	if err != nil {
		return nil, err
	}

	v := map[string]string{}
	for k, vv := range req.Form {
		if len(vv) == 0 {
			continue
		}
		v[k] = vv[0]
	}

	// reset form values
	req.Form = url.Values{}

	// pr, pw := io.Pipe()
	// req.Body = pr

	// go func() {
	// 	enc := json.NewEncoder(pw)
	// 	err := enc.Encode(v)
	// 	pw.CloseWithError(err)
	// }()

	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}

	req.ContentLength = int64(len(b))
	req.Header.Set("Content-Type", "application/json")
	req.Body = ioutil.NopCloser(bytes.NewBuffer(b))
	return rt.rtp.RoundTrip(req)
}
