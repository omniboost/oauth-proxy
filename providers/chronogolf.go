package providers

import (
	"context"

	"golang.org/x/oauth2"
)

type Chronogolf struct {
	name     string
	authURL  string
	tokenURL string
}

func NewChronogolf() *Chronogolf {
	return &Chronogolf{}
}

func (v Chronogolf) WithName(name string) Chronogolf {
	v.name = name
	return v
}

func (v Chronogolf) WithAuthURL(u string) Chronogolf {
	v.authURL = u
	return v
}

func (v Chronogolf) WithTokenURL(u string) Chronogolf {
	v.tokenURL = u
	return v
}

func (v Chronogolf) Name() string {
	return v.name
}

func (v Chronogolf) Route() string {
	return "/" + v.name + "/oauth2/token"
}

func (v Chronogolf) oauthConfig() *oauth2.Config {
	authURL := "https://www.chronogolf.com/oauth/auth"
	if v.authURL != "" {
		authURL = v.authURL
	}
	tokenURL := "https://www.chronogolf.com/oauth/token"
	if v.tokenURL != "" {
		tokenURL = v.tokenURL
	}

	return &oauth2.Config{
		RedirectURL:  "",
		ClientID:     "",
		ClientSecret: "",
		Scopes:       []string{},
		Endpoint: oauth2.Endpoint{
			AuthURL:   authURL,
			TokenURL:  tokenURL,
			AuthStyle: oauth2.AuthStyleInParams,
		},
	}
}

func (v Chronogolf) Exchange(ctx context.Context, params TokenRequestParams, opts ...oauth2.AuthCodeOption) (*oauth2.Token, error) {
	config := v.oauthConfig()
	config.ClientID = params.ClientID
	config.ClientSecret = params.ClientSecret
	config.RedirectURL = params.RedirectURL
	return config.Exchange(ctx, params.Code, opts...)
}

func (v Chronogolf) TokenSourceAuthorizationCode(ctx context.Context, params TokenRequestParams) oauth2.TokenSource {
	config := v.oauthConfig()
	config.ClientID = params.ClientID
	config.ClientSecret = params.ClientSecret
	config.RedirectURL = params.RedirectURL
	token := &oauth2.Token{
		RefreshToken: params.RefreshToken,
	}
	return config.TokenSource(ctx, token)
}
