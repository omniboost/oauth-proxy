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
	Exchange(context.Context, TokenRequestParams, ...oauth2.AuthCodeOption) (*oauth2.Token, error)
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
		NewExactOnline().
			WithName("exactonline.de").
			WithBaseURL(url.URL{
				Scheme: "https",
				Host:   "start.exactonline.de",
			}),
		NewQuickBooks().
			WithName("quickbooks"),
		NewIzettle().
			WithName("izettle"),
		NewMinox().
			WithName("minox"),
		NewApaleo().
			WithName("apaleo"),
		NewCloudbeds().
			WithName("cloudbeds.com"),
		NewXero().
			WithName("xero.com"),
		NewLightspeed().
			WithName("lightspeed.test").
			WithBaseURL(url.URL{
				Scheme: "https",
				Host:   "test.lightspeedapis.com",
			}),
		NewLightspeed().
			WithName("lightspeed").
			WithBaseURL(url.URL{
				Scheme: "https",
				Host:   "lightspeedapis.com",
			}),
		NewProcountor().
			WithName("procountor"),
		NewLightspeedRetail().
			WithName("ls_retail").
			WithBaseURL(url.URL{
				Scheme: "https",
				Host:   "cloud.lightspeedapp.com",
			}),
		NewApicbase().
			WithName("apicbase"),
		NewBizcuit().
			WithName("tst.bizcuit").
			WithBaseURL(url.URL{
				Scheme: "https",
				Host:   "tst.bizcuit.nl",
			}),
	}
}

type TokenRequestParams struct {
	ClientID     string
	ClientSecret string
	RefreshToken string
	Code         string
	RedirectURL  string
	CodeVerifier string
}
