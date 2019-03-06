package providers

import (
	"context"

	"golang.org/x/oauth2"
)

type Minox struct {
	name string
}

func NewMinox() *Minox {
	return &Minox{}
}

func (m Minox) WithName(name string) Minox {
	m.name = name
	return m
}

func (m Minox) Name() string {
	return m.name
}

func (m Minox) Route() string {
	return "/" + m.name + "/oauth/token"
}

func (m Minox) oauthConfig() *oauth2.Config {
	return &oauth2.Config{
		RedirectURL:  "",
		ClientID:     "",
		ClientSecret: "",
		Scopes:       []string{},
		Endpoint: oauth2.Endpoint{
			AuthURL:  "https://app.minox.nl/oauth/authorize",
			TokenURL: "https://app.minox.nl/oauth/token",
		},
	}
}

func (m Minox) Exchange(ctx context.Context, params TokenRequestParams, opts ...oauth2.AuthCodeOption) (*oauth2.Token, error) {
	config := m.oauthConfig()
	config.ClientID = params.ClientID
	config.ClientSecret = params.ClientSecret
	config.RedirectURL = params.RedirectURL
	return config.Exchange(ctx, params.Code, opts...)
}

func (m Minox) TokenSource(ctx context.Context, params TokenRequestParams) oauth2.TokenSource {
	config := m.oauthConfig()
	config.ClientID = params.ClientID
	config.ClientSecret = params.ClientSecret
	config.RedirectURL = params.RedirectURL
	token := &oauth2.Token{
		RefreshToken: params.RefreshToken,
	}
	return config.TokenSource(ctx, token)
}
