package providers

import (
	"context"
	"net/url"

	"golang.org/x/oauth2"
)

type Lightspeed struct {
	name    string
	baseURL url.URL
}

func NewLightspeed() *Lightspeed {
	return &Lightspeed{}
}

func (l Lightspeed) WithName(name string) Lightspeed {
	l.name = name
	return l
}

func (l Lightspeed) WithBaseURL(url url.URL) Lightspeed {
	l.baseURL = url
	return l
}

func (l Lightspeed) Name() string {
	return l.name
}

func (l Lightspeed) Route() string {
	return "/" + l.name + "/oauth2/token"
}

func (l Lightspeed) oauthConfig() *oauth2.Config {
	return &oauth2.Config{
		RedirectURL:  "",
		ClientID:     "",
		ClientSecret: "",
		Scopes:       []string{},
		Endpoint: oauth2.Endpoint{
			AuthURL:  l.baseURL.String() + "/resto/oauth2/v1/authorize",
			TokenURL: l.baseURL.String() + "/resto/oauth2/v1/token",
		},
	}
}

func (l Lightspeed) Exchange(ctx context.Context, params TokenRequestParams, opts ...oauth2.AuthCodeOption) (*oauth2.Token, error) {
	config := l.oauthConfig()
	config.ClientID = params.ClientID
	config.ClientSecret = params.ClientSecret
	config.RedirectURL = params.RedirectURL
	return config.Exchange(ctx, params.Code, opts...)
}

func (l Lightspeed) TokenSource(ctx context.Context, params TokenRequestParams) oauth2.TokenSource {
	config := l.oauthConfig()
	config.ClientID = params.ClientID
	config.ClientSecret = params.ClientSecret
	config.RedirectURL = params.RedirectURL
	token := &oauth2.Token{
		RefreshToken: params.RefreshToken,
	}
	return config.TokenSource(ctx, token)
}
