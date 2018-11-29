package providers

import (
	"context"
	"net/url"

	"golang.org/x/oauth2"
)

type QuickBooks struct {
	name    string
	baseURL url.URL
}

func NewQuickBooks() *QuickBooks {
	return &QuickBooks{}
}

func (qb QuickBooks) WithName(name string) QuickBooks {
	qb.name = name
	return qb
}

func (qb QuickBooks) Name() string {
	return qb.name
}

func (qb QuickBooks) Route() string {
	return "/" + qb.name + "/oauth2/v1/tokens/bearer"
}

func (qb QuickBooks) oauthConfig() *oauth2.Config {
	return &oauth2.Config{
		RedirectURL:  "",
		ClientID:     "",
		ClientSecret: "",
		Scopes:       []string{},
		Endpoint: oauth2.Endpoint{
			AuthURL:  "https://appcenter.intuit.com/connect/oauth2",
			TokenURL: "https://oauth.platform.intuit.com/oauth2/v1/tokens/bearer",
		},
	}
}

func (qb QuickBooks) Exchange(ctx context.Context, params TokenRequestParams, opts ...oauth2.AuthCodeOption) (*oauth2.Token, error) {
	config := qb.oauthConfig()
	config.ClientID = params.ClientID
	config.ClientSecret = params.ClientSecret
	config.RedirectURL = params.RedirectURL
	return config.Exchange(ctx, params.Code, opts...)
}

func (qb QuickBooks) TokenSource(ctx context.Context, params TokenRequestParams) oauth2.TokenSource {
	config := qb.oauthConfig()
	config.ClientID = params.ClientID
	config.ClientSecret = params.ClientSecret
	config.RedirectURL = params.RedirectURL
	token := &oauth2.Token{
		RefreshToken: params.RefreshToken,
	}
	return config.TokenSource(ctx, token)
}
