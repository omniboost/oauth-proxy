package providers

import (
	"context"

	"golang.org/x/oauth2"
)

type Adsolut struct {
	name     string
	authURL  string
	tokenURL string
}

func NewAdsolut() *Adsolut {
	return &Adsolut{}
}

func (v Adsolut) WithName(name string) Adsolut {
	v.name = name
	return v
}

func (v Adsolut) WithAuthURL(u string) Adsolut {
	v.authURL = u
	return v
}

func (v Adsolut) WithTokenURL(u string) Adsolut {
	v.tokenURL = u
	return v
}

func (v Adsolut) Name() string {
	return v.name
}

func (v Adsolut) Route() string {
	return "/" + v.name + "/oauth2/token"
}

func (v Adsolut) oauthConfig() *oauth2.Config {
	authURL := "https://login.wolterskluwer.eu/auth/core/connect/authorize"
	if v.authURL != "" {
		authURL = v.authURL
	}
	tokenURL := "https://login.wolterskluwer.eu/auth/core/connect/token"
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

func (v Adsolut) Exchange(ctx context.Context, params TokenRequestParams, opts ...oauth2.AuthCodeOption) (*oauth2.Token, error) {
	config := v.oauthConfig()
	config.ClientID = params.ClientID
	config.ClientSecret = params.ClientSecret
	config.RedirectURL = params.RedirectURL
	return config.Exchange(ctx, params.Code, opts...)
}

func (v Adsolut) TokenSource(ctx context.Context, params TokenRequestParams) oauth2.TokenSource {
	config := v.oauthConfig()
	config.ClientID = params.ClientID
	config.ClientSecret = params.ClientSecret
	config.RedirectURL = params.RedirectURL
	token := &oauth2.Token{
		RefreshToken: params.RefreshToken,
	}
	return config.TokenSource(ctx, token)
}
