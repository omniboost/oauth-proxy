package providers

import (
	"context"
	"encoding/json"
	"net/url"
	"strings"

	"github.com/pkg/errors"
	"golang.org/x/oauth2"
)

type NetSuite struct {
	name    string
	baseURL url.URL
}

func NewNetSuite() *NetSuite {
	return &NetSuite{}
}

func (ns NetSuite) WithName(name string) NetSuite {
	ns.name = name
	return ns
}

func (ns NetSuite) Name() string {
	return ns.name
}

func (ns NetSuite) Route() string {
	return "/" + ns.name + "/oauth2/authorize.nl"
}

func (ns NetSuite) oauthConfig() *oauth2.Config {
	return &oauth2.Config{
		RedirectURL:  "",
		ClientID:     "",
		ClientSecret: "",
		Scopes:       []string{},
		Endpoint: oauth2.Endpoint{
			AuthURL:  "https://system.netsuite.com/app/login/oauth2/authorize.nl",
			TokenURL: "https://{{.account_id}}.suitetalk.api.netsuite.com/services/rest/auth/oauth2/v1/token",
		},
	}
}

func (ns NetSuite) Exchange(ctx context.Context, params TokenRequestParams, opts ...oauth2.AuthCodeOption) (*oauth2.Token, error) {
	company := ""
	err := json.Unmarshal(params.Raw["company"], &company)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	config := ns.oauthConfig()
	config.Endpoint.TokenURL = strings.Replace(config.Endpoint.TokenURL, "{{.account_id}}", company, -1)
	config.ClientID = params.ClientID
	config.ClientSecret = params.ClientSecret
	config.RedirectURL = params.RedirectURL
	return config.Exchange(ctx, params.Code, opts...)
}

func (ns NetSuite) TokenSource(ctx context.Context, params TokenRequestParams) oauth2.TokenSource {
	config := ns.oauthConfig()
	config.ClientID = params.ClientID
	config.ClientSecret = params.ClientSecret
	config.RedirectURL = params.RedirectURL
	token := &oauth2.Token{
		RefreshToken: params.RefreshToken,
	}
	return config.TokenSource(ctx, token)
}
