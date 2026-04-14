package providers

import (
	"context"

	"golang.org/x/oauth2"
)

type LightspeedKSeries struct {
	name     string
	authURL  string
	tokenURL string
}

func NewLightspeedKSeries() *LightspeedKSeries {
	return &LightspeedKSeries{}
}

func (l LightspeedKSeries) WithName(name string) LightspeedKSeries {
	l.name = name
	return l
}

func (l LightspeedKSeries) WithAuthURL(u string) LightspeedKSeries {
	l.authURL = u
	return l
}

func (l LightspeedKSeries) WithTokenURL(u string) LightspeedKSeries {
	l.tokenURL = u
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
			AuthURL:  l.authURL,
			TokenURL: l.tokenURL,
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

func (l LightspeedKSeries) TokenSourceAuthorizationCode(ctx context.Context, params TokenRequestParams) oauth2.TokenSource {
	config := l.oauthConfig()
	config.ClientID = params.ClientID
	config.ClientSecret = params.ClientSecret
	config.RedirectURL = params.RedirectURL
	token := &oauth2.Token{
		RefreshToken: params.RefreshToken,
	}
	return config.TokenSource(ctx, token)
}
