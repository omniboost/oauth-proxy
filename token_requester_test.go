package oauthproxy_test

import (
	"context"
	"database/sql"
	"encoding/json"
	"testing"
	"time"

	oauthproxy "github.com/omniboost/oauth-proxy"
	"github.com/omniboost/oauth-proxy/mysql"
	"github.com/omniboost/oauth-proxy/providers"
	"github.com/pkg/errors"
	"golang.org/x/oauth2"
)

func TestTokenRequester(t *testing.T) {
	provider := NewMockProvider()
	tr := oauthproxy.NewTokenRequester(dbh, provider)
	now := time.Now()
	token := &oauth2.Token{
		AccessToken:  "TEST",
		RefreshToken: "TEST",
		Expiry:       now,
		TokenType:    "Bearer",
	}
	proxyToken := oauthproxy.Token{
		Token: token,
		Raw:   map[string]json.RawMessage{"test": []byte(`"TEST"`)},
	}
	params := providers.TokenRequestParams{
		ClientID:     "TEST",
		ClientSecret: "TEST",
		RefreshToken: "TEST",
		Code:         "",
		RedirectURL:  "http://localhost:8080",
		CodeVerifier: "",
	}

	tokenRequest, err := tr.SaveNewTokenRequest(params)
	if err != nil {
		t.Error(err)
		return
	}

	_, err = tr.TokenFromDB(params)
	if err == nil {
		t.Error("expected error, got nil")
		return
	}
	if errors.Cause(err) != sql.ErrNoRows {
		t.Errorf("expected sql.ErrNoRows, got %s", err)
		return
	}

	dbToken, err := tr.SaveToken(&proxyToken, params)
	if err != nil {
		t.Error(err)
		return
	}

	dbToken2, err := tr.DBTokenFromDB(params)
	if err != nil {
		t.Error(err)
		return
	}

	// dbToken & dbToken1 should have the same ID
	if dbToken.ID != dbToken2.ID {
		t.Errorf("expected same ID, got %d and %d", dbToken.ID, dbToken2.ID)
		return
	}

	// check if dbToken contains token fields
	if dbToken2.App != "TEST" {
		t.Errorf("expected TEST, got %s", dbToken2.App)
		return
	}
	if dbToken2.Type != "Bearer" {
		t.Errorf("expected Bearer, got %s", dbToken2.Type)
		return
	}
	if dbToken2.ClientID != "TEST" {
		t.Errorf("expected TEST, got %s", dbToken2.ClientID)
		return
	}
	if dbToken2.ClientSecret != "TEST" {
		t.Errorf("expected TEST, got %s", dbToken2.ClientSecret)
		return
	}
	if dbToken2.OriginalRefreshToken != "TEST" {
		t.Errorf("expected TEST, got %s", dbToken2.OriginalRefreshToken)
		return
	}
	if dbToken2.AccessToken != "TEST" {
		t.Errorf("expected TEST, got %s", dbToken2.AccessToken)
		return
	}
	if dbToken2.RefreshToken != "TEST" {
		t.Errorf("expected TEST, got %s", dbToken2.RefreshToken)
		return
	}
	if dbToken2.CodeExchangeResponseBody.String != `{"test":"TEST"}` {
		t.Errorf("expected %s, got %s", `{"test":"TEST"}`, dbToken2.CodeExchangeResponseBody.String)
		return
	}
	if dbToken2.ExpiresAt.Time.Equal(now) {
		t.Errorf("expected %s, got %s", dbToken2.ExpiresAt.Time, now)
		return
	}

	// add new token to token request
	tokenRequest, err = tr.AddTokenToTokenRequest(tokenRequest, proxyToken)
	if err != nil {
		t.Error(err)
		return
	}

	// tokenRequest should contain the token fields
	if tokenRequest.App != "TEST" {
		t.Errorf("expected TEST, got %s", tokenRequest.App)
		return
	}
	if tokenRequest.RequestClientID != "TEST" {
		t.Errorf("expected TEST, got %s", tokenRequest.RequestClientID)
		return
	}
	if tokenRequest.RequestClientSecret != "TEST" {
		t.Errorf("expected TEST, got %s", tokenRequest.RequestClientSecret)
		return
	}
	if tokenRequest.RequestRefreshToken != "TEST" {
		t.Errorf("expected TEST, got %s", tokenRequest.RequestRefreshToken)
		return
	}
	if tokenRequest.RequestCode != "" {
		t.Errorf("expected empty, got %s", tokenRequest.RequestCode)
		return
	}
	if tokenRequest.RequestRedirectURL != "http://localhost:8080" {
		t.Errorf("expected http://localhost:8080, got %s", tokenRequest.RequestRedirectURL)
		return
	}
	if tokenRequest.RequestCodeVerifier != "" {
		t.Errorf("expected empty, got %s", tokenRequest.RequestCodeVerifier)
		return
	}
	if tokenRequest.ResponseAccessToken != "TEST" {
		t.Errorf("expected TEST, got %s", tokenRequest.ResponseAccessToken)
		return
	}
	if tokenRequest.ResponseTokenType != "Bearer" {
		t.Errorf("expected Bearer, got %s", tokenRequest.ResponseTokenType)
		return
	}
	if tokenRequest.ResponseRefreshToken != "TEST" {
		t.Errorf("expected TEST, got %s", tokenRequest.ResponseRefreshToken)
		return
	}
	if tokenRequest.ResponseExpiry.Time != token.Expiry {
		t.Errorf("expected %s, got %s", token.Expiry, tokenRequest.ResponseExpiry.Time)
		return
	}
	if tokenRequest.ResponseExtra != `{"test":"TEST"}` {
		t.Errorf("expected %s, got %s", `{"test":"TEST"}`, tokenRequest.ResponseExtra)
		return
	}

	tokens, err := mysql.OauthTokensByAppAccessToken(context.Background(), dbh, provider.Name(), "TEST")
	if err != nil {
		t.Error(err)
		return
	}

	if len(tokens) == 0 {
		t.Error("no tokens found")
		return
	}
}

func TestTokenExpired(t *testing.T) {
	// test TokenRefresh
	// insert token in db with local timezone with expiry < 1 minute in the future
	// retrieve the token and see if it still is expired

	provider := NewMockProvider()
	tr := oauthproxy.NewTokenRequester(dbh, provider)

	now := time.Now()
	params := providers.TokenRequestParams{
		ClientID:     "TEST_TOKEN_EXPIRED",
		ClientSecret: "TEST_TOKEN_EXPIRED",
		RefreshToken: "TEST_TOKEN_EXPIRED",
		Code:         "",
		RedirectURL:  "http://localhost:8080",
		CodeVerifier: "",
	}
	token := &oauth2.Token{
		AccessToken:  "TEST_TOKEN_EXPIRED",
		RefreshToken: "TEST_TOKEN_EXPIRED",
		Expiry:       now.Add(time.Minute * -1),
		TokenType:    "Bearer",
	}
	proxyToken := oauthproxy.Token{
		Token: token,
		Raw:   map[string]json.RawMessage{},
	}
	_, err := tr.SaveToken(&proxyToken, params)
	if err != nil {
		t.Error(err)
		return
	}

	tokenRequest := tr.NewTokenRequest(params)
	newToken, err := tr.TokenRefresh(tokenRequest)
	if err != nil {
		t.Error(err)
		return
	}

	if newToken.RefreshToken != "MOCK" {
		t.Error("expected to receive a new token")
		return
	}
}

func TestTokenValid(t *testing.T) {
	// test TokenRefresh
	// insert token in db with local timezone with expiry < 1 minute in the future
	// retrieve the token and see if it still is expired

	provider := NewMockProvider()
	tr := oauthproxy.NewTokenRequester(dbh, provider)

	now := time.Now()
	params := providers.TokenRequestParams{
		ClientID:     "TEST_TOKEN_VALID",
		ClientSecret: "TEST_TOKEN_VALID",
		RefreshToken: "TEST_TOKEN_VALID",
		Code:         "",
		RedirectURL:  "http://localhost:8080",
		CodeVerifier: "",
	}
	token := &oauth2.Token{
		AccessToken:  "TEST_TOKEN_VALID",
		RefreshToken: "TEST_TOKEN_VALID",
		Expiry:       now.Add(time.Second * 20),
		TokenType:    "Bearer",
	}
	proxyToken := oauthproxy.Token{
		Token: token,
		Raw:   map[string]json.RawMessage{},
	}
	_, err := tr.SaveToken(&proxyToken, params)
	if err != nil {
		t.Error(err)
		return
	}

	tokenRequest := tr.NewTokenRequest(params)
	newToken, err := tr.TokenRefresh(tokenRequest)
	if err != nil {
		t.Error(err)
		return
	}

	if !newToken.Valid() {
		t.Errorf("expected token to be valid, but expired at %s", newToken.Expiry)
		return
	}

	if newToken.RefreshToken != "TEST_TOKEN_VALID" {
		t.Error("expected to receive the same token back, because it's still valid")
		return
	}
}
