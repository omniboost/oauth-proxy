package oauthproxy_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	oauthproxy "github.com/omniboost/oauth-proxy"
	"github.com/omniboost/oauth-proxy/mysql"
	"github.com/omniboost/oauth-proxy/providers"
	"golang.org/x/oauth2"
)

type RevokeTestProvider struct {
	revokeURL string
}

func (p RevokeTestProvider) Name() string        { return "REVOKE" }
func (p RevokeTestProvider) Route() string       { return "/REVOKE/oauth2/token" }
func (p RevokeTestProvider) RevokeRoute() string { return "/REVOKE/oauth2/revoke" }
func (p RevokeTestProvider) RevokeURL() string   { return p.revokeURL }

func TestRevokeRotatedRefreshToken(t *testing.T) {
	revoked := make(chan string, 1)
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Error(err)
		}
		revoked <- r.Form.Get("token")
	}))
	defer provider.Close()
	prov := RevokeTestProvider{revokeURL: provider.URL}

	// token row whose refresh token has been rotated once
	params := providers.TokenRequestParams{
		ClientID:     "REVOKE",
		ClientSecret: "REVOKE_SECRET",
		RefreshToken: "ORIGINAL_RT",
	}
	tr := oauthproxy.NewTokenRequester(dbh, prov)
	for _, refreshToken := range []string{"ORIGINAL_RT", "CURRENT_RT"} {
		_, err := tr.SaveAuthorizationToken(dbh, &oauthproxy.Token{
			Token: &oauth2.Token{
				AccessToken:  "AT",
				RefreshToken: refreshToken,
				Expiry:       time.Now().Add(time.Hour),
				TokenType:    "Bearer",
			},
			Raw: map[string]json.RawMessage{},
		}, params, nil)
		if err != nil {
			t.Fatal(err)
		}
	}
	dbToken, err := tr.AuthorizationTokenFromDB(dbh, params)
	if err != nil {
		t.Fatal(err)
	}
	if dbToken.RefreshToken != "CURRENT_RT" {
		t.Fatalf("expected rotated refresh token in db, got %s", dbToken.RefreshToken)
	}

	// the caller only knows the original refresh token
	form := url.Values{"token": {"ORIGINAL_RT"}, "token_type_hint": {"refresh_token"}}
	r := httptest.NewRequest(http.MethodPost, prov.RevokeRoute(), strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rv := oauthproxy.NewTokenRevoker(dbh, prov)
	rv.Start()
	resp, err := rv.Revoke(oauthproxy.TokenRevokeParams{
		ClientID:      params.ClientID,
		ClientSecret:  params.ClientSecret,
		Token:         "ORIGINAL_RT",
		TokenTypeHint: "refresh_token",
		Request:       r,
	})
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	select {
	case got := <-revoked:
		if got != "CURRENT_RT" {
			t.Errorf("expected current refresh token to be revoked at provider, got %q", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("provider revoke endpoint not called")
	}

	row, err := mysql.OauthTokenByID(context.Background(), dbh, dbToken.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !row.RefreshTokenExpiresAt.Valid {
		t.Error("expected refresh token to be marked as revoked in db")
	}
}

func TestRevokeClientCredentialsInForm(t *testing.T) {
	received := make(chan url.Values, 1)
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Error(err)
		}
		received <- r.PostForm
	}))
	defer provider.Close()
	prov := RevokeTestProvider{revokeURL: provider.URL}

	params := providers.TokenRequestParams{
		ClientID:     "REVOKE_FORM",
		ClientSecret: "REVOKE_FORM_SECRET",
		RefreshToken: "FORM_RT",
	}
	tr := oauthproxy.NewTokenRequester(dbh, prov)
	dbToken, err := tr.SaveAuthorizationToken(dbh, &oauthproxy.Token{
		Token: &oauth2.Token{
			AccessToken:  "FORM_AT",
			RefreshToken: "FORM_RT",
			Expiry:       time.Now().Add(time.Hour),
			TokenType:    "Bearer",
		},
		Raw: map[string]json.RawMessage{},
	}, params, nil)
	if err != nil {
		t.Fatal(err)
	}

	// client credentials in the form values instead of the authorization header
	form := url.Values{
		"token":           {"FORM_RT"},
		"token_type_hint": {"refresh_token"},
		"client_id":       {params.ClientID},
		"client_secret":   {params.ClientSecret},
	}
	r := httptest.NewRequest(http.MethodPost, prov.RevokeRoute(), strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	srv := &oauthproxy.Server{}
	rrp, err := srv.GetTokenRevokeParamsFromRequest(r)
	if err != nil {
		t.Fatal(err)
	}
	rv := oauthproxy.NewTokenRevoker(dbh, prov)
	rv.Start()
	resp, err := rv.Revoke(rrp)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	select {
	case got := <-received:
		if got.Get("client_id") != params.ClientID || got.Get("client_secret") != params.ClientSecret {
			t.Errorf("expected client credentials to be sent to provider, got %v", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("provider revoke endpoint not called")
	}

	row, err := mysql.OauthTokenByID(context.Background(), dbh, dbToken.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !row.RefreshTokenExpiresAt.Valid {
		t.Error("expected refresh token to be marked as revoked in db")
	}
}

func TestRevokeWithoutTokenTypeHint(t *testing.T) {
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer provider.Close()
	prov := RevokeTestProvider{revokeURL: provider.URL}

	tr := oauthproxy.NewTokenRequester(dbh, prov)
	save := func(clientID string) int {
		t.Helper()
		params := providers.TokenRequestParams{
			ClientID:     clientID,
			ClientSecret: clientID + "_SECRET",
			RefreshToken: clientID + "_RT",
		}
		dbToken, err := tr.SaveAuthorizationToken(dbh, &oauthproxy.Token{
			Token: &oauth2.Token{
				AccessToken:  clientID + "_AT",
				RefreshToken: clientID + "_RT",
				Expiry:       time.Now().Add(time.Hour),
				TokenType:    "Bearer",
			},
			Raw: map[string]json.RawMessage{},
		}, params, nil)
		if err != nil {
			t.Fatal(err)
		}
		return dbToken.ID
	}
	revoke := func(clientID, token string) {
		t.Helper()
		form := url.Values{"token": {token}, "client_id": {clientID}, "client_secret": {clientID + "_SECRET"}}
		r := httptest.NewRequest(http.MethodPost, prov.RevokeRoute(), strings.NewReader(form.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rrp, err := (&oauthproxy.Server{}).GetTokenRevokeParamsFromRequest(r)
		if err != nil {
			t.Fatal(err)
		}
		rv := oauthproxy.NewTokenRevoker(dbh, prov)
		rv.Start()
		resp, err := rv.Revoke(rrp)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
	}
	row := func(id int) *mysql.OauthToken {
		t.Helper()
		row, err := mysql.OauthTokenByID(context.Background(), dbh, id)
		if err != nil {
			t.Fatal(err)
		}
		return row
	}

	// refresh token without hint
	id := save("NOHINT_REFRESH")
	revoke("NOHINT_REFRESH", "NOHINT_REFRESH_RT")
	if !row(id).RefreshTokenExpiresAt.Valid {
		t.Error("expected refresh token to be marked as revoked in db")
	}

	// access token without hint
	id = save("NOHINT_ACCESS")
	revoke("NOHINT_ACCESS", "NOHINT_ACCESS_AT")
	r := row(id)
	if r.RefreshTokenExpiresAt.Valid {
		t.Error("expected refresh token not to be revoked when revoking an access token")
	}
	if !r.ExpiresAt.Valid || r.ExpiresAt.Time.After(time.Now()) {
		t.Errorf("expected access token to be expired, expires at %v", r.ExpiresAt.Time)
	}
}
