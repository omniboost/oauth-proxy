package providers

import (
	"context"
	"net/url"

	"golang.org/x/oauth2"
)

type MYOB struct {
	name    string
	baseURL url.URL
}

func NewMYOB() *MYOB {
	return &MYOB{}
}

func (m MYOB) WithName(name string) MYOB {
	m.name = name
	return m
}

func (m MYOB) WithBaseURL(url url.URL) MYOB {
	m.baseURL = url
	return m
}

func (m MYOB) Name() string {
	return m.name
}

func (m MYOB) Route() string {
	// "/exactonline.nl/api/oauth2/token"
	return "/" + m.name + "/api/oauth2/token"
}

func (m MYOB) oauthConfig() *oauth2.Config {
	return &oauth2.Config{
		RedirectURL:  "",
		ClientID:     "",
		ClientSecret: "",
		Scopes:       []string{},
		Endpoint: oauth2.Endpoint{
			AuthURL:  "https://secure.myob.com/oauth2/account/authorize",
			TokenURL: "https://secure.myob.com/oauth2/v1/authorize",
		},
	}
}

func (m MYOB) Exchange(ctx context.Context, params TokenRequestParams, opts ...oauth2.AuthCodeOption) (*oauth2.Token, error) {
	config := m.oauthConfig()
	config.ClientID = params.ClientID
	config.ClientSecret = params.ClientSecret
	config.RedirectURL = params.RedirectURL
	return config.Exchange(ctx, params.Code, opts...)
}

func (m MYOB) TokenSource(ctx context.Context, params TokenRequestParams) oauth2.TokenSource {
	config := m.oauthConfig()
	config.ClientID = params.ClientID
	config.ClientSecret = params.ClientSecret
	config.RedirectURL = params.RedirectURL
	token := &oauth2.Token{
		RefreshToken: params.RefreshToken,
	}
	return config.TokenSource(ctx, token)
}

// func (m MYOB) NewToken(ctx context.Context, params TokenRequestParams) (oauth2.Token, error) {
// 	tokenSource := eo.TokenSource(oauth2.NoContext, params)
// 	return tokenSource.Token()
// }
