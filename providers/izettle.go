package providers

import (
	"context"

	"golang.org/x/oauth2"
)

type Izettle struct {
	name string
}

func NewIzettle() *Izettle {
	return &Izettle{}
}

func (iz Izettle) WithName(name string) Izettle {
	iz.name = name
	return iz
}

func (iz Izettle) Name() string {
	return iz.name
}

func (iz Izettle) Route() string {
	return "/" + iz.name + "/token"
}

func (iz Izettle) oauthConfig() *oauth2.Config {
	return &oauth2.Config{
		RedirectURL:  "",
		ClientID:     "",
		ClientSecret: "",
		Scopes:       []string{},
		Endpoint: oauth2.Endpoint{
			AuthURL:   "https://oauth.izettle.net/authorize",
			TokenURL:  "https://oauth.izettle.net/token",
			AuthStyle: oauth2.AuthStyleInHeader,
		},
	}
}

func (iz Izettle) Exchange(ctx context.Context, params TokenRequestParams, opts ...oauth2.AuthCodeOption) (*oauth2.Token, error) {
	config := iz.oauthConfig()
	config.ClientID = params.ClientID
	config.ClientSecret = params.ClientSecret
	config.RedirectURL = params.RedirectURL
	return config.Exchange(ctx, params.Code, opts...)
}

func (iz Izettle) TokenSource(ctx context.Context, params TokenRequestParams) oauth2.TokenSource {
	config := iz.oauthConfig()
	config.ClientID = params.ClientID
	config.ClientSecret = params.ClientSecret
	config.RedirectURL = params.RedirectURL
	token := &oauth2.Token{
		RefreshToken: params.RefreshToken,
	}
	return config.TokenSource(ctx, token)
}
