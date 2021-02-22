package providers

import (
	"context"

	"golang.org/x/oauth2"
)

type Cockpit struct {
	name string
}

func NewCockpit() *Cockpit {
	return &Cockpit{}
}

func (m Cockpit) WithName(name string) Cockpit {
	m.name = name
	return m
}

func (m Cockpit) Name() string {
	return m.name
}

func (m Cockpit) Route() string {
	return "/" + m.name + "/oauth2/token"
}

func (m Cockpit) oauthConfig() *oauth2.Config {
	return &oauth2.Config{
		RedirectURL:  "",
		ClientID:     "",
		ClientSecret: "",
		Scopes:       []string{},
		Endpoint: oauth2.Endpoint{
			AuthURL:  "",
			TokenURL: "https://stage.posms.app.hd.digital/api/oAuth/token",
		},
	}
}

func (m Cockpit) Exchange(ctx context.Context, params TokenRequestParams, opts ...oauth2.AuthCodeOption) (*oauth2.Token, error) {
	config := m.oauthConfig()
	config.ClientID = params.ClientID
	config.ClientSecret = params.ClientSecret
	config.RedirectURL = params.RedirectURL
	return config.Exchange(ctx, params.Code, opts...)
}

func (m Cockpit) TokenSource(ctx context.Context, params TokenRequestParams) oauth2.TokenSource {
	config := m.oauthConfig()
	config.ClientID = params.ClientID
	config.ClientSecret = params.ClientSecret
	config.RedirectURL = params.RedirectURL
	token := &oauth2.Token{
		RefreshToken: params.RefreshToken,
	}
	return config.TokenSource(ctx, token)
}
