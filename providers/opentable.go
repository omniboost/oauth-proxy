package providers

import (
	"context"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"
)

type OpenTable struct {
	name     string
	authURL  string
	tokenURL string
}

func NewOpenTable() *OpenTable {
	return &OpenTable{}
}

func (v OpenTable) WithName(name string) OpenTable {
	v.name = name
	return v
}

func (v OpenTable) WithAuthURL(u string) OpenTable {
	v.authURL = u
	return v
}

func (v OpenTable) WithTokenURL(u string) OpenTable {
	v.tokenURL = u
	return v
}

func (v OpenTable) Name() string {
	return v.name
}

func (v OpenTable) Route() string {
	return "/" + v.name + "/oauth2/token"
}

func (v OpenTable) oauthConfig() *clientcredentials.Config {
	tokenURL := "https://oauth.opentable.com/api/v2/oauth/token"
	if v.tokenURL != "" {
		tokenURL = v.tokenURL
	}

	return &clientcredentials.Config{
		ClientID:     "",
		ClientSecret: "",
		Scopes:       []string{},
		TokenURL:     tokenURL,
	}
}

func (v OpenTable) TokenSourceClientCredentials(ctx context.Context, params TokenRequestParams) oauth2.TokenSource {
	config := v.oauthConfig()
	config.ClientID = params.ClientID
	config.ClientSecret = params.ClientSecret
	return config.TokenSource(ctx)
}
