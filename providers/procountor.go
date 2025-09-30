package providers

import (
	"context"

	"golang.org/x/oauth2"
)

type Procountor struct {
	name string
}

func NewProcountor() *Procountor {
	return &Procountor{}
}

func (m Procountor) WithName(name string) Procountor {
	m.name = name
	return m
}

func (m Procountor) Name() string {
	return m.name
}

func (m Procountor) Route() string {
	return "/" + m.name + "/oauth/token"
}

func (m Procountor) oauthConfig() *oauth2.Config {
	return &oauth2.Config{
		RedirectURL:  "",
		ClientID:     "",
		ClientSecret: "",
		Scopes:       []string{},
		Endpoint: oauth2.Endpoint{
			AuthURL:   "https://api.procountor.com/api/oauth/login",
			TokenURL:  "https://api.procountor.com/api/oauth/token",
			AuthStyle: oauth2.AuthStyleInParams,
		},
	}
}

func (m Procountor) Exchange(ctx context.Context, params TokenRequestParams, opts ...oauth2.AuthCodeOption) (*oauth2.Token, error) {
	config := m.oauthConfig()
	config.ClientID = params.ClientID
	config.ClientSecret = params.ClientSecret
	config.RedirectURL = params.RedirectURL

	opts = append(opts, oauth2.SetAuthURLParam("client_id", config.ClientID), oauth2.SetAuthURLParam("client_secret", config.ClientSecret))
	return config.Exchange(ctx, params.Code, opts...)
}

func (m Procountor) TokenSourceAuthorizationCode(ctx context.Context, params TokenRequestParams) oauth2.TokenSource {
	config := m.oauthConfig()
	config.ClientID = params.ClientID
	config.ClientSecret = params.ClientSecret
	config.RedirectURL = params.RedirectURL
	token := &oauth2.Token{
		RefreshToken: params.RefreshToken,
	}
	return config.TokenSource(ctx, token)
}
