package providers

import (
	"context"
	"encoding/json"
	"net/http"
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

type RevokeProvider interface {
	Name() string
	RevokeRoute() string
	RevokeURL() string
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
		NewExactOnline().
			WithName("exactonline.com").
			WithBaseURL(url.URL{
				Scheme: "https",
				Host:   "one.exactonline.com",
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
		NewLightspeedKSeries().
			WithName("lightspeed-k-series").
			WithBaseURL(url.URL{
				Scheme: "https",
				Host:   "nightswatch.ikentoo.com",
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
		NewCockpit().
			WithName("cockpit"),
		NewNetSuite().
			WithName("netsuite"),
		NewAmadeus().
			WithName("amadeus"),
		NewFortnox().
			WithName("fortnox"),
		NewAsperion().
			WithName("asperion"),
		NewVismaNet().
			WithName("visma.net"),
		NewVismaOnline().
			WithName("vismaonline").
			WithAuthURL("https://identity.vismaonline.com/connect/authorize").
			WithTokenURL("https://identity.vismaonline.com/connect/token"),
		NewAdsolut().
			WithName("adsolut"),
		NewChronogolf().
			WithName("chronogolf"),
		NewDatev().
			WithName("datev").
			WithRemoteKeysetURL("https://api.datev.de/certs").
			WithIssuerURL("https://login.datev.de/openid").
			WithRevokeURL("https://api.datev.de/revoke"),
		NewDatev().
			WithName("datev-sandbox").
			WithAuthURL("https://login.datev.de/openidsandbox/authorize").
			WithTokenURL("https://sandbox-api.datev.de/token").
			WithRemoteKeysetURL("https://sandbox-api.datev.de/certs").
			WithIssuerURL("https://login.datev.de/openidsandbox").
			WithRevokeURL("https://sandbox-api.datev.de/revoke"),
		NewBookingExperts().
			WithName("bookingexperts"),
	}
}

type TokenRequestParams struct {
	ClientID     string
	ClientSecret string
	RefreshToken string
	Code         string
	RedirectURL  string
	CodeVerifier string

	Raw             map[string]json.RawMessage
	OriginalRequest *http.Request
}
