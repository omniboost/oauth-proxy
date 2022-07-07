package providers

import (
	"context"
	"net/url"

	"golang.org/x/oauth2"
)

type Apicbase struct {
	name    string
	baseURL url.URL
}

func NewApicbase() *Apicbase {
	return &Apicbase{}
}

func (ab Apicbase) WithName(name string) Apicbase {
	ab.name = name
	return ab
}

func (ab Apicbase) Name() string {
	return ab.name
}

func (ab Apicbase) Route() string {
	return "/" + ab.name + "/oauth/token"
}

func (ab Apicbase) oauthConfig() *oauth2.Config {
	return &oauth2.Config{
		RedirectURL:  "",
		ClientID:     "",
		ClientSecret: "",
		Scopes:       []string{},
		Endpoint: oauth2.Endpoint{
			AuthURL:  "",
			TokenURL: "https://app.apicbase.com/oauth/token/",
		},
	}
}

func (ab Apicbase) Exchange(ctx context.Context, params TokenRequestParams, opts ...oauth2.AuthCodeOption) (*oauth2.Token, error) {
	config := ab.oauthConfig()
	config.ClientID = params.ClientID
	config.ClientSecret = params.ClientSecret
	config.RedirectURL = params.RedirectURL
	return config.Exchange(ctx, params.Code, opts...)
}

func (ab Apicbase) TokenSource(ctx context.Context, params TokenRequestParams) oauth2.TokenSource {
	config := ab.oauthConfig()
	config.ClientID = params.ClientID
	config.ClientSecret = params.ClientSecret
	config.RedirectURL = params.RedirectURL
	token := &oauth2.Token{
		RefreshToken: params.RefreshToken,
	}
	return config.TokenSource(ctx, token)
}
