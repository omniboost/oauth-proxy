package providers

import (
	"context"

	"golang.org/x/oauth2"
)

type Asperion struct {
	name string
}

func NewAsperion() *Asperion {
	return &Asperion{}
}

func (f Asperion) WithName(name string) Asperion {
	f.name = name
	return f
}

func (f Asperion) Name() string {
	return f.name
}

func (f Asperion) Route() string {
	return "/" + f.name + "/oauth2/token"
}

func (f Asperion) oauthConfig() *oauth2.Config {
	return &oauth2.Config{
		RedirectURL:  "",
		ClientID:     "",
		ClientSecret: "",
		Scopes:       []string{},
		Endpoint: oauth2.Endpoint{
			AuthURL:   "https://identity.asperion.nl/connect/authorize",
			TokenURL:  "https://identity.asperion.nl/connect/token",
			AuthStyle: oauth2.AuthStyleInParams,
		},
	}
}

func (f Asperion) Exchange(ctx context.Context, params TokenRequestParams, opts ...oauth2.AuthCodeOption) (*oauth2.Token, error) {
	config := f.oauthConfig()
	config.ClientID = params.ClientID
	config.ClientSecret = params.ClientSecret
	config.RedirectURL = params.RedirectURL
	return config.Exchange(ctx, params.Code, opts...)
}

func (f Asperion) TokenSource(ctx context.Context, params TokenRequestParams) oauth2.TokenSource {
	config := f.oauthConfig()
	config.ClientID = params.ClientID
	config.ClientSecret = params.ClientSecret
	config.RedirectURL = params.RedirectURL
	token := &oauth2.Token{
		RefreshToken: params.RefreshToken,
	}
	return config.TokenSource(ctx, token)
}
