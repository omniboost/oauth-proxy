package providers

import (
	"context"

	"github.com/joefitzgerald/passwordcredentials"
	"golang.org/x/oauth2"
)

type Shiji struct {
	name     string
	authURL  string
	tokenURL string
}

func NewShiji() *Shiji {
	return &Shiji{}
}

func (v Shiji) WithName(name string) Shiji {
	v.name = name
	return v
}

func (v Shiji) WithAuthURL(u string) Shiji {
	v.authURL = u
	return v
}

func (v Shiji) WithTokenURL(u string) Shiji {
	v.tokenURL = u
	return v
}

func (v Shiji) Name() string {
	return v.name
}

func (v Shiji) Route() string {
	return "/" + v.name + "/oauth2/token"
}

func (v Shiji) oauthConfig() *passwordcredentials.Config {
	tokenURL := "https://eu1.api.uat.development.abovecloud.io/connect/token"
	if v.tokenURL != "" {
		tokenURL = v.tokenURL
	}

	return &passwordcredentials.Config{
		ClientID:     "",
		ClientSecret: "",
		Scopes:       []string{},
		Endpoint: oauth2.Endpoint{
			AuthURL:  "",
			TokenURL: tokenURL,
		},
	}
}

func (v Shiji) TokenSource(ctx context.Context, params TokenRequestParams) oauth2.TokenSource {
	config := v.oauthConfig()
	config.ClientID = params.ClientID
	config.ClientSecret = params.ClientSecret
	config.Username = params.Username
	config.Password = params.Password
	return config.TokenSource(ctx)
}
