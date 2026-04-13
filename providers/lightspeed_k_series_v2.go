package providers

import (
	"context"
	"net/url"

	"golang.org/x/oauth2"
)

type LightspeedKSeriesV2 struct {
	name    string
	baseURL url.URL
}

func NewLightspeedKSeriesV2() *LightspeedKSeriesV2 {
	return &LightspeedKSeriesV2{}
}

func (l LightspeedKSeriesV2) WithName(name string) LightspeedKSeriesV2 {
	l.name = name
	return l
}

func (l LightspeedKSeriesV2) WithBaseURL(url url.URL) LightspeedKSeriesV2 {
	l.baseURL = url
	return l
}

func (l LightspeedKSeriesV2) Name() string {
	return l.name
}

func (l LightspeedKSeriesV2) Route() string {
	return "/" + l.name + "/oauth2/token"
}

func (l LightspeedKSeriesV2) oauthConfig() *oauth2.Config {
	return &oauth2.Config{
		RedirectURL:  "",
		ClientID:     "",
		ClientSecret: "",
		Scopes:       []string{},
		Endpoint: oauth2.Endpoint{
			AuthURL:  l.baseURL.String() + "/realms/k-series/protocol/openid-connect/auth",
			TokenURL: l.baseURL.String() + "/realms/k-series/protocol/openid-connect/token",
		},
	}
}

func (l LightspeedKSeriesV2) Exchange(ctx context.Context, params TokenRequestParams, opts ...oauth2.AuthCodeOption) (*oauth2.Token, error) {
	config := l.oauthConfig()
	config.ClientID = params.ClientID
	config.ClientSecret = params.ClientSecret
	config.RedirectURL = params.RedirectURL
	return config.Exchange(ctx, params.Code, opts...)
}

func (l LightspeedKSeriesV2) TokenSourceAuthorizationCode(ctx context.Context, params TokenRequestParams) oauth2.TokenSource {
	config := l.oauthConfig()
	config.ClientID = params.ClientID
	config.ClientSecret = params.ClientSecret
	config.RedirectURL = params.RedirectURL
	token := &oauth2.Token{
		RefreshToken: params.RefreshToken,
	}
	return config.TokenSource(ctx, token)
}
