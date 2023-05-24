package providers

import (
	"context"

	"golang.org/x/oauth2"
)

type Datev struct {
	name     string
	authURL  string
	tokenURL string
}

func NewDatev() *Datev {
	return &Datev{}
}

func (v Datev) WithName(name string) Datev {
	v.name = name
	return v
}

func (v Datev) WithAuthURL(u string) Datev {
	v.authURL = u
	return v
}

func (v Datev) WithTokenURL(u string) Datev {
	v.tokenURL = u
	return v
}

func (v Datev) Name() string {
	return v.name
}

func (v Datev) Route() string {
	return "/" + v.name + "/oauth2/token"
}

func (v Datev) oauthConfig() *oauth2.Config {
	authURL := "https://login.datev.de/openid/authorize"
	if v.authURL != "" {
		authURL = v.authURL
	}
	tokenURL := "https://api.datev.de/token"
	if v.tokenURL != "" {
		tokenURL = v.tokenURL
	}

	return &oauth2.Config{
		RedirectURL:  "",
		ClientID:     "",
		ClientSecret: "",
		Scopes:       []string{},
		Endpoint: oauth2.Endpoint{
			AuthURL:   authURL,
			TokenURL:  tokenURL,
			AuthStyle: oauth2.AuthStyleInHeader,
		},
	}
}

func (v Datev) Exchange(ctx context.Context, params TokenRequestParams, opts ...oauth2.AuthCodeOption) (*oauth2.Token, error) {
	config := v.oauthConfig()
	config.ClientID = params.ClientID
	config.ClientSecret = params.ClientSecret
	config.RedirectURL = params.RedirectURL
	return config.Exchange(ctx, params.Code, opts...)
}

func (v Datev) TokenSource(ctx context.Context, params TokenRequestParams) oauth2.TokenSource {
	config := v.oauthConfig()
	config.ClientID = params.ClientID
	config.ClientSecret = params.ClientSecret
	config.RedirectURL = params.RedirectURL
	token := &oauth2.Token{
		RefreshToken: params.RefreshToken,
	}
	return config.TokenSource(ctx, token)
}
