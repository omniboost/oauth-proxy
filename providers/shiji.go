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

func (v Shiji) passwordOauthConfig() *passwordcredentials.Config {
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

func (v Shiji) authorizationCodeOauthConfig() *oauth2.Config {
	tokenURL := "https://eu1.api.uat.development.abovecloud.io/connect/token"
	if v.tokenURL != "" {
		tokenURL = v.tokenURL
	}

	return &oauth2.Config{
		ClientID:     "",
		ClientSecret: "",
		Scopes:       []string{},
		Endpoint: oauth2.Endpoint{
			AuthURL:  "",
			TokenURL: tokenURL,
		},
	}
}

func (v Shiji) Exchange(ctx context.Context, params TokenRequestParams, opts ...oauth2.AuthCodeOption) (*oauth2.Token, error) {
	config := v.authorizationCodeOauthConfig()
	config.ClientID = params.ClientID
	config.ClientSecret = params.ClientSecret
	config.RedirectURL = params.RedirectURL
	return config.Exchange(ctx, params.Code, opts...)
}

func (v Shiji) TokenSource(ctx context.Context, params TokenRequestParams) oauth2.TokenSource {
	if params.RefreshToken == "" {
		config := v.passwordOauthConfig()
		config.ClientID = params.ClientID
		config.ClientSecret = params.ClientSecret
		config.Username = params.Username
		config.Password = params.Password
		return config.TokenSource(ctx)
	}

	config := v.authorizationCodeOauthConfig()
	config.ClientID = params.ClientID
	config.ClientSecret = params.ClientSecret
	config.RedirectURL = params.RedirectURL
	token := &oauth2.Token{
		RefreshToken: params.RefreshToken,
	}
	return config.TokenSource(ctx, token)
}
