package providers

import (
	"context"

	"golang.org/x/oauth2"
)

type VismaOnline struct {
	name     string
	authURL  string
	tokenURL string
}

func NewVismaOnline() *VismaOnline {
	return &VismaOnline{}
}

func (v VismaOnline) WithName(name string) VismaOnline {
	v.name = name
	return v
}

func (v VismaOnline) WithAuthURL(u string) VismaOnline {
	v.authURL = u
	return v
}

func (v VismaOnline) WithTokenURL(u string) VismaOnline {
	v.tokenURL = u
	return v
}

func (v VismaOnline) Name() string {
	return v.name
}

func (v VismaOnline) Route() string {
	return "/" + v.name + "/oauth2/token"
}

func (v VismaOnline) oauthConfig() *oauth2.Config {
	authURL := "https://identity.vismaonline.com/connect/authorize"
	if v.authURL != "" {
		authURL = v.authURL
	}
	tokenURL := "https://identity.vismaonline.com/connect/token"
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

func (v VismaOnline) Exchange(ctx context.Context, params TokenRequestParams, opts ...oauth2.AuthCodeOption) (*oauth2.Token, error) {
	config := v.oauthConfig()
	config.ClientID = params.ClientID
	config.ClientSecret = params.ClientSecret
	config.RedirectURL = params.RedirectURL
	return config.Exchange(ctx, params.Code, opts...)
}

func (v VismaOnline) TokenSource(ctx context.Context, params TokenRequestParams) oauth2.TokenSource {
	config := v.oauthConfig()
	config.ClientID = params.ClientID
	config.ClientSecret = params.ClientSecret
	config.RedirectURL = params.RedirectURL
	token := &oauth2.Token{
		RefreshToken: params.RefreshToken,
	}
	return config.TokenSource(ctx, token)
}
