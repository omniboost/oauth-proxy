package oauthproxy

import (
	"encoding/json"

	"golang.org/x/oauth2"
)

type Token struct {
	*oauth2.Token
	Raw map[string]json.RawMessage
}
