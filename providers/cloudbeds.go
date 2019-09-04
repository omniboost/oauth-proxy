package providers

import (
	"context"

	"golang.org/x/oauth2"
)

func init() {
}

type Cloudbeds struct {
	name string
}

func NewCloudbeds() *Cloudbeds {
	return &Cloudbeds{}
}

func (m Cloudbeds) WithName(name string) Cloudbeds {
	m.name = name
	return m
}

func (m Cloudbeds) Name() string {
	return m.name
}

func (m Cloudbeds) Route() string {
	return "/" + m.name + "/oauth2/token"
}

func (m Cloudbeds) oauthConfig() *oauth2.Config {
	return &oauth2.Config{
		RedirectURL:  "",
		ClientID:     "",
		ClientSecret: "",
		Scopes:       []string{},
		Endpoint: oauth2.Endpoint{
			AuthURL:  "https://hotels.cloudbeds.com/api/v1.1/oauth",
			TokenURL: "https://hotels.cloudbeds.com/api/v1.1/access_token",
		},
	}
}

func (m Cloudbeds) Exchange(ctx context.Context, params TokenRequestParams, opts ...oauth2.AuthCodeOption) (*oauth2.Token, error) {
	config := m.oauthConfig()
	config.ClientID = params.ClientID
	config.ClientSecret = params.ClientSecret
	config.RedirectURL = params.RedirectURL
	return config.Exchange(ctx, params.Code, opts...)
}

func (m Cloudbeds) TokenSource(ctx context.Context, params TokenRequestParams) oauth2.TokenSource {
	config := m.oauthConfig()
	config.ClientID = params.ClientID
	config.ClientSecret = params.ClientSecret
	config.RedirectURL = params.RedirectURL
	token := &oauth2.Token{
		RefreshToken: params.RefreshToken,
	}
	return config.TokenSource(ctx, token)
}
