package providers

import (
	"context"

	"golang.org/x/oauth2"
)

type VismaNet struct {
	name     string
	authURL  string
	tokenURL string
}

func NewVismaNet() *VismaNet {
	return &VismaNet{}
}

func (v VismaNet) WithName(name string) VismaNet {
	v.name = name
	return v
}

func (v VismaNet) WithAuthURL(u string) VismaNet {
	v.authURL = u
	return v
}

func (v VismaNet) WithTokenURL(u string) VismaNet {
	v.tokenURL = u
	return v
}

func (v VismaNet) Name() string {
	return v.name
}

func (v VismaNet) Route() string {
	return "/" + v.name + "/oauth2/token"
}

func (v VismaNet) oauthConfig() *oauth2.Config {
	return &oauth2.Config{
		RedirectURL:  "",
		ClientID:     "",
		ClientSecret: "",
		Scopes:       []string{},
		Endpoint: oauth2.Endpoint{
			AuthURL:  "https://connect.visma.com/connect/authorize",
			TokenURL: "https://connect.visma.com/connect/token",
		},
	}
}

func (v VismaNet) Exchange(ctx context.Context, params TokenRequestParams, opts ...oauth2.AuthCodeOption) (*oauth2.Token, error) {
	config := v.oauthConfig()
	config.ClientID = params.ClientID
	config.ClientSecret = params.ClientSecret
	config.RedirectURL = params.RedirectURL
	return config.Exchange(ctx, params.Code, opts...)
}

func (v VismaNet) TokenSource(ctx context.Context, params TokenRequestParams) oauth2.TokenSource {
	config := v.oauthConfig()
	config.ClientID = params.ClientID
	config.ClientSecret = params.ClientSecret
	config.RedirectURL = params.RedirectURL
	token := &oauth2.Token{
		RefreshToken: params.RefreshToken,
	}
	return config.TokenSource(ctx, token)
}
