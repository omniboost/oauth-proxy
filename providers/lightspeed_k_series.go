package providers

import (
	"context"
	"net/url"

	"golang.org/x/oauth2"
)

type LightspeedKSeries struct {
	name    string
	baseURL url.URL
}

func NewLightspeedKSeries() *LightspeedKSeries {
	return &LightspeedKSeries{}
}

func (l LightspeedKSeries) WithName(name string) LightspeedKSeries {
	l.name = name
	return l
}

func (l LightspeedKSeries) WithBaseURL(url url.URL) LightspeedKSeries {
	l.baseURL = url
	return l
}

func (l LightspeedKSeries) Name() string {
	return l.name
}

func (l LightspeedKSeries) Route() string {
	return "/" + l.name + "/oauth2/token"
}

func (l LightspeedKSeries) oauthConfig() *oauth2.Config {
	return &oauth2.Config{
		RedirectURL:  "",
		ClientID:     "",
		ClientSecret: "",
		Scopes:       []string{},
		Endpoint: oauth2.Endpoint{
			AuthURL:  l.baseURL.String() + "/oauth/authorize",
			TokenURL: l.baseURL.String() + "/oauth/token",
		},
	}
}

func (l LightspeedKSeries) Exchange(ctx context.Context, params TokenRequestParams, opts ...oauth2.AuthCodeOption) (*oauth2.Token, error) {
	config := l.oauthConfig()
	config.ClientID = params.ClientID
	config.ClientSecret = params.ClientSecret
	config.RedirectURL = params.RedirectURL
	return config.Exchange(ctx, params.Code, opts...)
}

func (l LightspeedKSeries) TokenSource(ctx context.Context, params TokenRequestParams) oauth2.TokenSource {
	config := l.oauthConfig()
	config.ClientID = params.ClientID
	config.ClientSecret = params.ClientSecret
	config.RedirectURL = params.RedirectURL
	token := &oauth2.Token{
		RefreshToken: params.RefreshToken,
	}
	return config.TokenSource(ctx, token)
}
