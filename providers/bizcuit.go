package providers

import (
	"context"
	"net/url"

	"golang.org/x/oauth2"
)

func init() {
	oauth2.RegisterBrokenAuthHeaderProvider("https://tst.bizcuit.nl")
}

type Bizcuit struct {
	name    string
	baseURL url.URL
}

func NewBizcuit() *Bizcuit {
	return &Bizcuit{}
}

func (p Bizcuit) WithName(name string) Bizcuit {
	p.name = name
	return p
}

func (p Bizcuit) WithBaseURL(url url.URL) Bizcuit {
	p.baseURL = url
	return p
}

func (p Bizcuit) Name() string {
	return p.name
}

func (p Bizcuit) Route() string {
	return "/" + p.name + "/oauth/token"
}

func (p Bizcuit) oauthConfig() *oauth2.Config {
	return &oauth2.Config{
		RedirectURL:  "",
		ClientID:     "",
		ClientSecret: "",
		Scopes:       []string{},
		Endpoint: oauth2.Endpoint{
			AuthURL:  p.baseURL.String() + "/auth",
			TokenURL: p.baseURL.String() + "/openapi/oauth/token",
		},
	}
}

func (p Bizcuit) Exchange(ctx context.Context, params TokenRequestParams, opts ...oauth2.AuthCodeOption) (*oauth2.Token, error) {
	config := p.oauthConfig()
	config.ClientID = params.ClientID
	config.ClientSecret = params.ClientSecret
	config.RedirectURL = params.RedirectURL
	// config.Endpoint.TokenURL = config.Endpoint.TokenURL + fmt.Sprintf(
	// 	"?client_id=%s&client_secret=%s&redirect_uri=%s&grant_type=%s&code=%s",
	// 	config.ClientID,
	// 	config.ClientSecret,
	// 	config.RedirectURL,
	// 	"authorization_code",
	// 	params.Code,
	// )
	return config.Exchange(ctx, params.Code, opts...)
}

func (p Bizcuit) TokenSource(ctx context.Context, params TokenRequestParams) oauth2.TokenSource {
	config := p.oauthConfig()
	config.ClientID = params.ClientID
	config.ClientSecret = params.ClientSecret
	config.RedirectURL = params.RedirectURL
	token := &oauth2.Token{
		RefreshToken: params.RefreshToken,
	}
	return config.TokenSource(ctx, token)
}

type AuthCodeOptionClientID struct {
	clientID string
}
