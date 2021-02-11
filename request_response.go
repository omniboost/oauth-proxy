package oauthproxy

import (
	"encoding/json"

	"github.com/pkg/errors"
)

type RawMessages map[string]json.RawMessage

type TokenRequestBody struct {
	RefreshToken string `json:"refresh_token"`
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	Code         string `json:"code"`
	RedirectURL  string `json:"redirect_uri"`
	CodeVerifier string `json:"code_verifier,omitempty"`

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
		"code":          &rb.Code,
		"redirect_uri":  &rb.RedirectURL,
		"code_verifier": &rb.CodeVerifier,
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

func (rb TokenResponseBody) MarshalJSON() ([]byte, error) {
	var err error

	mappings := rb.RawMessages

	// Overwrite old values
	mappings["token_type"], err = json.Marshal(rb.TokenType)
	if err != nil {
		return []byte{}, errors.WithStack(err)
	}
	mappings["access_token"], err = json.Marshal(rb.AccessToken)
	if err != nil {
		return []byte{}, errors.WithStack(err)
	}
	mappings["refresh_token"], err = json.Marshal(rb.RefreshToken)
	if err != nil {
		return []byte{}, errors.WithStack(err)
	}
	mappings["expires_in"], err = json.Marshal(rb.ExpiresIn)
	if err != nil {
		return []byte{}, errors.WithStack(err)
	}

	return json.Marshal(mappings)
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
