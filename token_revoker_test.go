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
