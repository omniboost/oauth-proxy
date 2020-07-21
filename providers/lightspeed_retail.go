package providers

import (
	"context"
	"net/url"

	"golang.org/x/oauth2"
)

type LightspeedRetail struct {
	name    string
	baseURL url.URL
}

func NewLightspeedRetail() *LightspeedRetail {
	return &LightspeedRetail{}
}

func (l LightspeedRetail) WithName(name string) LightspeedRetail {
	l.name = name
	return l
}

func (l LightspeedRetail) WithBaseURL(url url.URL) LightspeedRetail {
	l.baseURL = url
	return l
}

func (l LightspeedRetail) Name() string {
	return l.name
}

func (l LightspeedRetail) Route() string {
	return "/" + l.name + "/oauth2/token"
}

func (l LightspeedRetail) oauthConfig() *oauth2.Config {
	return &oauth2.Config{
		RedirectURL:  "",
		ClientID:     "",
		ClientSecret: "",
		Scopes:       []string{},
		Endpoint: oauth2.Endpoint{
			AuthURL:  l.baseURL.String() + "/oauth/authorize.php",
			TokenURL: l.baseURL.String() + "/oauth/access_token.php",
		},
	}
}

func (l LightspeedRetail) Exchange(ctx context.Context, params TokenRequestParams, opts ...oauth2.AuthCodeOption) (*oauth2.Token, error) {
	config := l.oauthConfig()
	config.ClientID = params.ClientID
	config.ClientSecret = params.ClientSecret
	config.RedirectURL = params.RedirectURL
	return config.Exchange(ctx, params.Code, opts...)
}

func (l LightspeedRetail) TokenSource(ctx context.Context, params TokenRequestParams) oauth2.TokenSource {
	config := l.oauthConfig()
	config.ClientID = params.ClientID
	config.ClientSecret = params.ClientSecret
	config.RedirectURL = params.RedirectURL
	token := &oauth2.Token{
		RefreshToken: params.RefreshToken,
	}
	return config.TokenSource(ctx, token)
}
