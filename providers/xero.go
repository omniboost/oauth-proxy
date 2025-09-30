package providers

import (
	"context"
	"net/url"

	"golang.org/x/oauth2"
)

type Xero struct {
	name    string
	baseURL url.URL
}

func NewXero() *Xero {
	return &Xero{}
}

func (x Xero) WithName(name string) Xero {
	x.name = name
	return x
}

func (x Xero) Name() string {
	return x.name
}

func (x Xero) Route() string {
	return "/" + x.name + "/connect/token"
}

func (x Xero) oauthConfig() *oauth2.Config {
	return &oauth2.Config{
		RedirectURL:  "",
		ClientID:     "",
		ClientSecret: "",
		Scopes:       []string{},
		Endpoint: oauth2.Endpoint{
			AuthURL:  "https://login.xero.com/identity/connect/authorize",
			TokenURL: "https://identity.xero.com/connect/token",
		},
	}
}

func (x Xero) Exchange(ctx context.Context, params TokenRequestParams, opts ...oauth2.AuthCodeOption) (*oauth2.Token, error) {
	config := x.oauthConfig()
	config.ClientID = params.ClientID
	config.ClientSecret = params.ClientSecret
	config.RedirectURL = params.RedirectURL
	return config.Exchange(ctx, params.Code, opts...)
}

func (x Xero) TokenSourceAuthorizationCode(ctx context.Context, params TokenRequestParams) oauth2.TokenSource {
	config := x.oauthConfig()
	config.ClientID = params.ClientID
	config.ClientSecret = params.ClientSecret
	config.RedirectURL = params.RedirectURL
	token := &oauth2.Token{
		RefreshToken: params.RefreshToken,
	}
	return config.TokenSource(ctx, token)
}
