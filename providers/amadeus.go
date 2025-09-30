package providers

import (
	"context"
	"net/http"

	"golang.org/x/oauth2"
)

type Amadeus struct {
	name string
}

func NewAmadeus() *Amadeus {
	return &Amadeus{}
}

func (am Amadeus) WithName(name string) Amadeus {
	am.name = name
	return am
}

func (am Amadeus) Name() string {
	return am.name
}

func (am Amadeus) Route() string {
	// https://api-release.amadeus-hospitality.com/release/2.0/OAuth2/RefreshAccessToken
	return "/" + am.name + "/OAuth2/RefreshAccessToken"
}

func (am Amadeus) oauthConfig() *oauth2.Config {
	return &oauth2.Config{
		RedirectURL:  "",
		ClientID:     "",
		ClientSecret: "",
		Scopes:       []string{},
		Endpoint: oauth2.Endpoint{
			AuthURL:  "https://api-release.amadeus-hospitality.com/release/2.0/OAuth2/AccessToken",
			TokenURL: "https://api-release.amadeus-hospitality.com/release/2.0/OAuth2/RefreshAccessToken",
		},
	}
}

func (am Amadeus) Exchange(ctx context.Context, params TokenRequestParams, opts ...oauth2.AuthCodeOption) (*oauth2.Token, error) {
	config := am.oauthConfig()
	config.ClientID = params.ClientID
	config.ClientSecret = params.ClientSecret
	config.RedirectURL = params.RedirectURL
	return config.Exchange(ctx, params.Code, opts...)
}

func (am Amadeus) TokenSourceAuthorizationCode(ctx context.Context, params TokenRequestParams) oauth2.TokenSource {
	config := am.oauthConfig()
	config.ClientID = params.ClientID
	config.ClientSecret = params.ClientSecret
	config.RedirectURL = params.RedirectURL
	token := &oauth2.Token{
		RefreshToken: params.RefreshToken,
	}

	rtp := NewAdditionalHeadersRoundTripper(http.DefaultTransport)
	rtp.Headers = map[string]string{
		"Ocp-Apim-Subscription-Key": params.OriginalRequest.Header.Get("Ocp-Apim-Subscription-Key"),
	}
	client := &http.Client{Transport: rtp}
	ctx = context.WithValue(ctx, oauth2.HTTPClient, client)

	return config.TokenSource(ctx, token)
}
