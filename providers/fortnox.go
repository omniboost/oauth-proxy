package providers

import (
	"context"

	"golang.org/x/oauth2"
)

type Fortnox struct {
	name string
}

func NewFortnox() *Fortnox {
	return &Fortnox{}
}

func (f Fortnox) WithName(name string) Fortnox {
	f.name = name
	return f
}

func (f Fortnox) Name() string {
	return f.name
}

func (f Fortnox) Route() string {
	// https://api-release.amadeus-hospitality.com/release/2.0/OAuth2/RefreshAccessToken
	return "/" + f.name + "/oauth2/token"
}

func (f Fortnox) oauthConfig() *oauth2.Config {
	return &oauth2.Config{
		RedirectURL:  "",
		ClientID:     "",
		ClientSecret: "",
		Scopes:       []string{},
		Endpoint: oauth2.Endpoint{
			AuthURL:   "https://apps.fortnox.se/oauth-v1/auth",
			TokenURL:  "https://apps.fortnox.se/oauth-v1/token",
			AuthStyle: oauth2.AuthStyleInHeader,
		},
	}
}

func (f Fortnox) Exchange(ctx context.Context, params TokenRequestParams, opts ...oauth2.AuthCodeOption) (*oauth2.Token, error) {
	config := f.oauthConfig()
	config.ClientID = params.ClientID
	config.ClientSecret = params.ClientSecret
	config.RedirectURL = params.RedirectURL
	return config.Exchange(ctx, params.Code, opts...)
}

func (f Fortnox) TokenSourceAuthorizationCode(ctx context.Context, params TokenRequestParams) oauth2.TokenSource {
	config := f.oauthConfig()
	config.ClientID = params.ClientID
	config.ClientSecret = params.ClientSecret
	config.RedirectURL = params.RedirectURL
	token := &oauth2.Token{
		RefreshToken: params.RefreshToken,
	}
	return config.TokenSource(ctx, token)
}
