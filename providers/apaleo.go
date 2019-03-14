package providers

import (
	"context"

	"golang.org/x/oauth2"
)

type Apaleo struct {
	name string
}

func NewApaleo() *Apaleo {
	return &Apaleo{}
}

func (m Apaleo) WithName(name string) Apaleo {
	m.name = name
	return m
}

func (m Apaleo) Name() string {
	return m.name
}

func (m Apaleo) Route() string {
	return "/" + m.name + "/oauth/token"
}

func (m Apaleo) oauthConfig() *oauth2.Config {
	return &oauth2.Config{
		RedirectURL:  "",
		ClientID:     "",
		ClientSecret: "",
		Scopes:       []string{},
		Endpoint: oauth2.Endpoint{
			AuthURL:  "https://identity.apaleo.com/connect/authorize",
			TokenURL: "https://identity.apaleo.com/connect/token",
		},
	}
}

func (m Apaleo) Exchange(ctx context.Context, params TokenRequestParams, opts ...oauth2.AuthCodeOption) (*oauth2.Token, error) {
	config := m.oauthConfig()
	config.ClientID = params.ClientID
	config.ClientSecret = params.ClientSecret
	config.RedirectURL = params.RedirectURL
	return config.Exchange(ctx, params.Code, opts...)
}

func (m Apaleo) TokenSource(ctx context.Context, params TokenRequestParams) oauth2.TokenSource {
	config := m.oauthConfig()
	config.ClientID = params.ClientID
	config.ClientSecret = params.ClientSecret
	config.RedirectURL = params.RedirectURL
	token := &oauth2.Token{
		RefreshToken: params.RefreshToken,
	}
	return config.TokenSource(ctx, token)
}
