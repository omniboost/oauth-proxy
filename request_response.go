package oauthproxy

import (
	"encoding/json"
)

type RawMessages map[string]json.RawMessage

type TokenRequestBody struct {
	RefreshToken string `json:"refresh_token"`
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`

	RawMessages
}

func (rb *TokenRequestBody) UnmarshalJSON(data []byte) error {
	err := json.Unmarshal(data, &rb.RawMessages)
	if err != nil {
		return err
	}

	mappings := map[string]interface{}{
		"refresh_token": &rb.RefreshToken,
		"client_id":     &rb.ClientID,
		"client_secret": &rb.ClientSecret,
	}

	for k, v := range mappings {
		if _, ok := rb.RawMessages[k]; ok {
			err = json.Unmarshal(rb.RawMessages[k], v)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

func (rb TokenRequestBody) Validate() []error {
	var errors []error
	return errors
}

type TokenResponseBody struct {
	TokenType    string `json:"token_type"`
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int    `json:"expires_in"`

	RawMessages `json:"-"`
}

func (rb *TokenResponseBody) UnmarshalJSON(data []byte) error {
	err := json.Unmarshal(data, &rb.RawMessages)
	if err != nil {
		return err
	}

	mappings := map[string]interface{}{
		"token_type":    &rb.TokenType,
		"access_token":  &rb.AccessToken,
		"refresh_token": &rb.RefreshToken,
		"expires_in":    &rb.ExpiresIn,
	}

	for k, v := range mappings {
		if _, ok := rb.RawMessages[k]; ok {
			err = json.Unmarshal(rb.RawMessages[k], v)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

type ErrorResponse struct {
	// acceptable:
	// - invalid_request
	// - invalid_client
	// - invalid_grant
	// - invalid_scope
	// - unauthorized_client
	// - unsupported_grant_type
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description,omitempty"`
	ErrorURI         string `json:"error_uri,omitempty"`
}
