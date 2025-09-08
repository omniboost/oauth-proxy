package providers

import (
	"bytes"
	"context"
	"text/template"

	"golang.org/x/oauth2"
)

type MicrosoftOnline struct {
	name string
}

func NewMicrosoftOnline() *MicrosoftOnline {
	return &MicrosoftOnline{}
}

func (f MicrosoftOnline) WithName(name string) MicrosoftOnline {
	f.name = name
	return f
}

func (f MicrosoftOnline) Name() string {
	return f.name
}

func (f MicrosoftOnline) Route() string {
	// https://api-release.amadeus-hospitality.com/release/2.0/OAuth2/RefreshAccessToken
	return "/" + f.name + "/oauth2/token"
}

func (f MicrosoftOnline) oauthConfig() *oauth2.Config {
	return &oauth2.Config{
		RedirectURL:  "",
		ClientID:     "",
		ClientSecret: "",
		Scopes:       []string{},
		Endpoint: oauth2.Endpoint{
			AuthURL:   "https://login.microsoftonline.com/{{.Tenant}}/oauth2/v2.0/authorize",
			TokenURL:  "https://login.microsoftonline.com/{{.Tenant}}/oauth2/v2.0/token",
			AuthStyle: oauth2.AuthStyleInHeader,
		},
	}
}

func (f MicrosoftOnline) Exchange(ctx context.Context, params TokenRequestParams, opts ...oauth2.AuthCodeOption) (*oauth2.Token, error) {
	config := f.oauthConfig()
	config.ClientID = params.ClientID
	config.ClientSecret = params.ClientSecret
	config.RedirectURL = params.RedirectURL

	tenant := params.OriginalRequest.PathValue("tenant")
	if tenant == "" {
		tenant = "common"
	}

	buf := bytes.NewBuffer([]byte{})
	tmpl, _ := template.New("microsoft_token_url").Parse(config.Endpoint.TokenURL)
	tmpl.Execute(buf, map[string]any{"Tenant": tenant})
	config.Endpoint.TokenURL = buf.String()

	return config.Exchange(ctx, params.Code, opts...)
}

func (f MicrosoftOnline) TokenSource(ctx context.Context, params TokenRequestParams) oauth2.TokenSource {
	config := f.oauthConfig()
	config.ClientID = params.ClientID
	config.ClientSecret = params.ClientSecret
	config.RedirectURL = params.RedirectURL
	token := &oauth2.Token{
		RefreshToken: params.RefreshToken,
	}

	tenant := params.OriginalRequest.PathValue("tenant")
	if tenant == "" {
		tenant = "common"
	}

	buf := bytes.NewBuffer([]byte{})
	tmpl, _ := template.New("microsoft_token_url").Parse(config.Endpoint.TokenURL)
	tmpl.Execute(buf, map[string]any{"Tenant": tenant})
	config.Endpoint.TokenURL = buf.String()
	return config.TokenSource(ctx, token)
}
