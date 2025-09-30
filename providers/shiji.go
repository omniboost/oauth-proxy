package providers

import (
	"bytes"
	"context"
	"text/template"

	"github.com/joefitzgerald/passwordcredentials"
	"golang.org/x/oauth2"
)

type Shiji struct {
	name     string
	authURL  string
	tokenURL string
}

func NewShiji() *Shiji {
	return &Shiji{}
}

func (v Shiji) WithName(name string) Shiji {
	v.name = name
	return v
}

func (v Shiji) WithAuthURL(u string) Shiji {
	v.authURL = u
	return v
}

func (v Shiji) WithTokenURL(u string) Shiji {
	v.tokenURL = u
	return v
}

func (v Shiji) Name() string {
	return v.name
}

func (v Shiji) Route() string {
	return "/" + v.name + "/oauth2/token"
}

func (v Shiji) passwordOauthConfig() *passwordcredentials.Config {
	tokenURL := "https://eu1.api.uat.development.abovecloud.io/connect/token"
	if v.tokenURL != "" {
		tokenURL = v.tokenURL
	}

	return &passwordcredentials.Config{
		ClientID:     "",
		ClientSecret: "",
		Scopes:       []string{},
		Endpoint: oauth2.Endpoint{
			AuthURL:  "",
			TokenURL: tokenURL,
		},
	}
}

func (v Shiji) authorizationCodeOauthConfig() *oauth2.Config {
	tokenURL := "https://eu1.api.uat.development.abovecloud.io/connect/token"
	if v.tokenURL != "" {
		tokenURL = v.tokenURL
	}

	return &oauth2.Config{
		ClientID:     "",
		ClientSecret: "",
		Scopes:       []string{},
		Endpoint: oauth2.Endpoint{
			AuthURL:  "",
			TokenURL: tokenURL,
		},
	}
}

func (v Shiji) Exchange(ctx context.Context, params TokenRequestParams, opts ...oauth2.AuthCodeOption) (*oauth2.Token, error) {
	config := v.authorizationCodeOauthConfig()
	config.ClientID = params.ClientID
	config.ClientSecret = params.ClientSecret
	config.RedirectURL = params.RedirectURL
	return config.Exchange(ctx, params.Code, opts...)
}

func (v Shiji) TokenSourcePassword(ctx context.Context, params TokenRequestParams) oauth2.TokenSource {
	return ShijiTokenSource{
		provider: v,
		ctx:      ctx,
		params:   params,
	}
}

type ShijiTokenSource struct {
	provider Shiji
	ctx      context.Context
	params   TokenRequestParams
}

func (v ShijiTokenSource) Token() (*oauth2.Token, error) {
	region := v.params.OriginalRequest.PathValue("region")
	if region == "" {
		region = "eu1"
	}

	buf := bytes.NewBuffer([]byte{})
	tmpl, _ := template.New("shiji_token_url").Parse(v.provider.tokenURL)
	tmpl.Execute(buf, map[string]any{"Region": region})
	tokenURL := buf.String()

	// We have a prior refresh token: get new access token with the refresh
	// token using the authorization_code grant_type flow
	if v.params.RefreshToken != "" {
		config := v.provider.authorizationCodeOauthConfig()
		config.ClientID = v.params.ClientID
		config.ClientSecret = v.params.ClientSecret
		config.RedirectURL = v.params.RedirectURL
		config.Endpoint.TokenURL = tokenURL
		token := &oauth2.Token{
			RefreshToken: v.params.RefreshToken,
		}

		ts := config.TokenSource(v.ctx, token)
		token, err := ts.Token()

		// call is done succesfuly: return the retrieved token
		if err == nil {
			return token, nil
		}

		// invalid response, we're going to use the initial
		// password oauth call again
	}

	// have no refresh token, or we get an error on the authorization code flow:
	// try the password grant_type flow
	config := v.provider.passwordOauthConfig()
	config.ClientID = v.params.ClientID
	config.ClientSecret = v.params.ClientSecret
	config.Username = v.params.Username
	config.Password = v.params.Password
	config.Endpoint.TokenURL = tokenURL

	// Initialize tokensource & get a new token
	ts := config.TokenSource(v.ctx)
	token, err := ts.Token()
	return token, err
}
