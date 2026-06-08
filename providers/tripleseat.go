package providers

import (
	"context"

	"golang.org/x/oauth2"
)

type Tripleseat struct {
	name     string
	authURL  string
	tokenURL string
}

func NewTripleseat() *Tripleseat {
	return &Tripleseat{
		authURL:  "https://login.tripleseat.com/oauth2/authorize",
		tokenURL: "https://api.tripleseat.com/oauth2/token",
	}
}

func (t Tripleseat) WithName(name string) Tripleseat {
	t.name = name
	return t
}

func (t Tripleseat) Name() string {
	return t.name
}

func (t Tripleseat) Route() string {
	return "/" + t.name + "/oauth2/token"
}

func (t Tripleseat) oauthConfig() *oauth2.Config {
	return &oauth2.Config{
		RedirectURL:  "",
		ClientID:     "",
		ClientSecret: "",
		Scopes:       []string{},
		Endpoint: oauth2.Endpoint{
			AuthURL:  t.authURL,
			TokenURL: t.tokenURL,
		},
	}
}

func (t Tripleseat) Exchange(ctx context.Context, params TokenRequestParams, opts ...oauth2.AuthCodeOption) (*oauth2.Token, error) {
	config := t.oauthConfig()
	config.ClientID = params.ClientID
	config.ClientSecret = params.ClientSecret
	config.RedirectURL = params.RedirectURL
	return config.Exchange(ctx, params.Code, opts...)
}

func (t Tripleseat) TokenSourceAuthorizationCode(ctx context.Context, params TokenRequestParams) oauth2.TokenSource {
	config := t.oauthConfig()
	config.ClientID = params.ClientID
	config.ClientSecret = params.ClientSecret
	config.RedirectURL = params.RedirectURL
	token := &oauth2.Token{
		RefreshToken: params.RefreshToken,
	}
	return config.TokenSource(ctx, token)
}
