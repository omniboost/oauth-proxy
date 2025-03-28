package providers

import (
	"bytes"
	"context"
	"text/template"

	"github.com/joefitzgerald/passwordcredentials"
	"golang.org/x/oauth2"
)

type HIA struct {
	name     string
	authURL  string
	tokenURL string
}

func NewHIA() *HIA {
	return &HIA{}
}

func (v HIA) WithName(name string) HIA {
	v.name = name
	return v
}

func (v HIA) WithAuthURL(u string) HIA {
	v.authURL = u
	return v
}

func (v HIA) WithTokenURL(u string) HIA {
	v.tokenURL = u
	return v
}

func (v HIA) Name() string {
	return v.name
}

func (v HIA) Route() string {
	return "/" + v.name + "/oauth2/token"
}

func (v HIA) passwordOauthConfig() *passwordcredentials.Config {
	tokenURL := "https://{{.Subdomain}}.hotelinvestorapps.com/identity/connect/token"
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

func (v HIA) authorizationCodeOauthConfig() *oauth2.Config {
	tokenURL := "https://{{.Subdomain}}.hotelinvestorapps.com/identity/connect/token"
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

func (v HIA) Exchange(ctx context.Context, params TokenRequestParams, opts ...oauth2.AuthCodeOption) (*oauth2.Token, error) {
	config := v.authorizationCodeOauthConfig()
	config.ClientID = params.ClientID
	config.ClientSecret = params.ClientSecret
	config.RedirectURL = params.RedirectURL
	return config.Exchange(ctx, params.Code, opts...)
}

func (v HIA) TokenSource(ctx context.Context, params TokenRequestParams) oauth2.TokenSource {
	return HIATokenSource{
		provider: v,
		ctx:      ctx,
		params:   params,
	}
}

type HIATokenSource struct {
	provider HIA
	ctx      context.Context
	params   TokenRequestParams
}

func (v HIATokenSource) Token() (*oauth2.Token, error) {
	subdomain := v.params.OriginalRequest.PathValue("subdomain")

	buf := bytes.NewBuffer([]byte{})
	tmpl, _ := template.New("hia_token_url").Parse(v.provider.tokenURL)
	tmpl.Execute(buf, map[string]any{"Subdomain": subdomain})
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
