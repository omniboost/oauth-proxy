package providers

import (
	"context"
	"net/url"

	"golang.org/x/oauth2"
)

type Providers []Provider

type Provider interface {
	Name() string
	Route() string
	// OauthConfig() oauth2.Config
	TokenSource(context.Context, TokenRequestParams) oauth2.TokenSource
	// NewToken(TokenRequestParams) (oauth2.Token, error)
}

func Load() Providers {
	return Providers{
		NewExactOnline().
			WithName("exactonline.nl").
			WithBaseURL(url.URL{
				Scheme: "https",
				Host:   "start.exactonline.nl",
			}),
		NewExactOnline().
			WithName("exactonline.be").
			WithBaseURL(url.URL{
				Scheme: "https",
				Host:   "start.exactonline.be",
			}),
		NewExactOnline().
			WithName("exactonline.fr").
			WithBaseURL(url.URL{
				Scheme: "https",
				Host:   "start.exactonline.fr",
			}),
	}
}

type TokenRequestParams struct {
	ClientID     string
	ClientSecret string
	RefreshToken string
}
