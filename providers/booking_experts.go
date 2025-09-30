package providers

import (
	"context"

	"golang.org/x/oauth2"
)

type BookingExperts struct {
	name     string
	authURL  string
	tokenURL string
}

func NewBookingExperts() *BookingExperts {
	return &BookingExperts{}
}

func (v BookingExperts) WithName(name string) BookingExperts {
	v.name = name
	return v
}

func (v BookingExperts) WithAuthURL(u string) BookingExperts {
	v.authURL = u
	return v
}

func (v BookingExperts) WithTokenURL(u string) BookingExperts {
	v.tokenURL = u
	return v
}

func (v BookingExperts) Name() string {
	return v.name
}

func (v BookingExperts) Route() string {
	return "/" + v.name + "/oauth2/token"
}

func (v BookingExperts) oauthConfig() *oauth2.Config {
	authURL := ""
	if v.authURL != "" {
		authURL = v.authURL
	}
	tokenURL := "https://app.bookingexperts.nl/oauth/token"
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

func (v BookingExperts) Exchange(ctx context.Context, params TokenRequestParams, opts ...oauth2.AuthCodeOption) (*oauth2.Token, error) {
	config := v.oauthConfig()
	config.ClientID = params.ClientID
	config.ClientSecret = params.ClientSecret
	config.RedirectURL = params.RedirectURL
	return config.Exchange(ctx, params.Code, opts...)
}

func (v BookingExperts) TokenSourceAuthorizationCode(ctx context.Context, params TokenRequestParams) oauth2.TokenSource {
	config := v.oauthConfig()
	config.ClientID = params.ClientID
	config.ClientSecret = params.ClientSecret
	config.RedirectURL = params.RedirectURL
	token := &oauth2.Token{
		RefreshToken: params.RefreshToken,
	}
	return config.TokenSource(ctx, token)
}
