package providers

import (
	"context"
	"net/url"

	"golang.org/x/oauth2"
)

type ExactOnline struct {
	name    string
	baseURL url.URL
}

func NewExactOnline() *ExactOnline {
	return &ExactOnline{}
}

func (eo ExactOnline) WithName(name string) ExactOnline {
	eo.name = name
	return eo
}

func (eo ExactOnline) WithBaseURL(url url.URL) ExactOnline {
	eo.baseURL = url
	return eo
}

func (eo ExactOnline) Name() string {
	return eo.name
}

func (eo ExactOnline) Route() string {
	// "/exactonline.nl/api/oauth2/token"
	return "/" + eo.name + "/api/oauth2/token"
}

func (eo ExactOnline) oauthConfig() *oauth2.Config {
	return &oauth2.Config{
		RedirectURL:  "",
		ClientID:     "",
		ClientSecret: "",
		Scopes:       []string{},
		Endpoint: oauth2.Endpoint{
			AuthURL:  eo.baseURL.String() + "/api/oauth2/auth",
			TokenURL: eo.baseURL.String() + "/api/oauth2/token",
		},
	}
}

func (eo ExactOnline) Exchange(ctx context.Context, params TokenRequestParams, opts ...oauth2.AuthCodeOption) (*oauth2.Token, error) {
	config := eo.oauthConfig()
	config.ClientID = params.ClientID
	config.ClientSecret = params.ClientSecret
	config.RedirectURL = params.RedirectURL
	return config.Exchange(ctx, params.Code, opts...)
}

func (eo ExactOnline) TokenSource(ctx context.Context, params TokenRequestParams) oauth2.TokenSource {
	config := eo.oauthConfig()
	config.ClientID = params.ClientID
	config.ClientSecret = params.ClientSecret
	config.RedirectURL = params.RedirectURL
	token := &oauth2.Token{
		RefreshToken: params.RefreshToken,
	}
	return config.TokenSource(ctx, token)
}

// func (eo ExactOnline) NewToken(ctx context.Context, params TokenRequestParams) (oauth2.Token, error) {
// 	tokenSource := eo.TokenSource(oauth2.NoContext, params)
// 	return tokenSource.Token()
// }
