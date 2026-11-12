package oauthproxy_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/getsentry/sentry-go"
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
	transport := &sentry.MockTransport{}
	client, err := sentry.NewClient(sentry.ClientOptions{Dsn: "https://public@sentry.invalid/1", Transport: transport})
	if err != nil {
		t.Fatal(err)
	}
	hub := sentry.NewHub(client, sentry.NewScope())

	rv := oauthproxy.NewTokenRevoker(dbh, prov)
	rv.Start()
	resp, err := rv.Revoke(oauthproxy.TokenRevokeParams{
		ClientID:      params.ClientID,
		ClientSecret:  params.ClientSecret,
		Token:         "ORIGINAL_RT",
		TokenTypeHint: "refresh_token",
		Request:       r,
	}, hub)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	// the worker tags the request's sentry events with the token row
	hub.CaptureMessage("test")
	if got, want := transport.Events()[0].Tags["TokenID"], strconv.Itoa(dbToken.ID); got != want {
		t.Errorf("expected TokenID tag %s, got %q", want, got)
	}

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
	resp, err := rv.Revoke(rrp, nil)
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
	// The no-hint access-token fallback must release its failed refresh-token
	// lookup transaction before using the pool again.
	dbh.SetMaxOpenConns(1)
	defer dbh.SetMaxOpenConns(0)
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
		resp, err := rv.Revoke(rrp, nil)
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

func TestRevokeReleasesLockOnProviderFailure(t *testing.T) {
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer provider.Close()
	for _, revokeURL := range []string{provider.URL, ":invalid-url"} {
		t.Run(revokeURL, func(t *testing.T) {
			prov := RevokeTestProvider{revokeURL: revokeURL}
			params := providers.TokenRequestParams{ClientID: revokeURL, ClientSecret: "SECRET", RefreshToken: "FAILED_RT"}
			tr := oauthproxy.NewTokenRequester(dbh, prov)
			_, err := tr.SaveAuthorizationToken(dbh, &oauthproxy.Token{
				Token: &oauth2.Token{AccessToken: "AT", RefreshToken: params.RefreshToken, TokenType: "Bearer", Expiry: time.Now().Add(time.Hour)},
				Raw:   map[string]json.RawMessage{},
			}, params, nil)
			if err != nil {
				t.Fatal(err)
			}
			rv := oauthproxy.NewTokenRevoker(dbh, prov)
			rv.Start()
			r := httptest.NewRequest(http.MethodPost, prov.RevokeRoute(), nil)
			resp, err := rv.Revoke(oauthproxy.TokenRevokeParams{ClientID: params.ClientID, ClientSecret: params.ClientSecret, Token: params.RefreshToken, TokenTypeHint: "refresh_token", Request: r}, nil)
			if resp != nil {
				resp.Body.Close()
				if resp.StatusCode != http.StatusBadRequest {
					t.Errorf("unexpected provider status %d", resp.StatusCode)
				}
			} else if err == nil {
				t.Fatal("expected provider response or request error")
			}

			// An independent transaction must be able to lock the same row.
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			trx, err := dbh.BeginTx(ctx, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer trx.Rollback()
			row, err := mysql.OauthTokenByAppClientIDClientSecretRefreshTokenOrOriginalRefreshToken(ctx, trx, prov.Name(), params.ClientID, params.ClientSecret, params.RefreshToken)
			if err != nil {
				t.Fatalf("revoke left row locked: %v", err)
			}
			if row.RefreshTokenExpiresAt.Valid {
				t.Error("failed provider request marked token as revoked")
			}
		})
	}
}

// blockingRefreshSource lets the tests keep the real refresh worker inside its
// transaction while the revoke worker tries to lock the same token row.
type blockingRefreshSource struct {
	started chan struct{}
	release chan struct{}
	token   *oauth2.Token
	err     error
}

func (s blockingRefreshSource) Token() (*oauth2.Token, error) {
	close(s.started)
	<-s.release
	return s.token, s.err
}

type concurrentRevokeProvider struct {
	RevokeTestProvider
	source oauth2.TokenSource
}

func (p concurrentRevokeProvider) Exchange(context.Context, providers.TokenRequestParams, ...oauth2.AuthCodeOption) (*oauth2.Token, error) {
	return p.source.Token()
}

func (p concurrentRevokeProvider) TokenSourceAuthorizationCode(context.Context, providers.TokenRequestParams) oauth2.TokenSource {
	return p.source
}

func TestRefreshAndRevokeSerialize(t *testing.T) {
	for _, refreshFirst := range []bool{true, false} {
		name := "revoke_first"
		if refreshFirst {
			name = "refresh_first"
		}
		t.Run(name, func(t *testing.T) {
			refreshStarted, releaseRefresh := make(chan struct{}), make(chan struct{})
			revoked, releaseRevoke := make(chan string, 1), make(chan struct{})
			var refreshOnce, revokeOnce sync.Once
			defer refreshOnce.Do(func() { close(releaseRefresh) })
			defer revokeOnce.Do(func() { close(releaseRevoke) })
			provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if err := r.ParseForm(); err != nil {
					t.Error(err)
					return
				}
				revoked <- r.Form.Get("token")
				<-releaseRevoke
			}))
			t.Cleanup(provider.Close)
			source := blockingRefreshSource{
				started: refreshStarted, release: releaseRefresh,
				token: &oauth2.Token{AccessToken: "NEW_AT", RefreshToken: "NEW_RT", TokenType: "Bearer", Expiry: time.Now().Add(time.Hour)},
			}
			if !refreshFirst {
				// The provider refuses a refresh attempted after revocation.
				source.err = errors.New("invalid_grant")
			}
			prov := concurrentRevokeProvider{RevokeTestProvider{revokeURL: provider.URL}, source}
			params := providers.TokenRequestParams{ClientID: name, ClientSecret: "SECRET", RefreshToken: "ORIGINAL_RT"}
			tr := oauthproxy.NewTokenRequester(dbh, prov)
			saved, err := tr.SaveAuthorizationToken(dbh, &oauthproxy.Token{
				Token: &oauth2.Token{AccessToken: "OLD_AT", RefreshToken: "ORIGINAL_RT", TokenType: "Bearer", Expiry: time.Now().Add(-time.Hour)},
				Raw:   map[string]json.RawMessage{},
			}, params, nil)
			if err != nil {
				t.Fatal(err)
			}
			tr.Start()
			rv := oauthproxy.NewTokenRevoker(dbh, prov)
			rv.Start()
			refreshDone, revokeDone := make(chan error, 1), make(chan error, 1)
			startRefresh := func() {
				go func() {
					_, err := tr.Request(params, nil, nil)
					refreshDone <- err
				}()
			}
			startRevoke := func() {
				go func() {
					r := httptest.NewRequest(http.MethodPost, prov.RevokeRoute(), nil)
					r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
					resp, err := rv.Revoke(oauthproxy.TokenRevokeParams{ClientID: params.ClientID, ClientSecret: params.ClientSecret, Token: params.RefreshToken, TokenTypeHint: "refresh_token", Request: r}, nil)
					if resp != nil {
						resp.Body.Close()
					}
					revokeDone <- err
				}()
			}
			if refreshFirst {
				startRefresh()
				select {
				case <-refreshStarted:
				case <-time.After(2 * time.Second):
					t.Fatal("refresh did not reach provider")
				}
				startRevoke()
				select {
				case token := <-revoked:
					t.Fatalf("revoke bypassed refresh lock and sent %q", token)
				case <-time.After(100 * time.Millisecond):
				}
				refreshOnce.Do(func() { close(releaseRefresh) })
				select {
				case token := <-revoked:
					if token != "NEW_RT" {
						t.Fatalf("revoke sent %q instead of the committed refresh token", token)
					}
				case <-time.After(2 * time.Second):
					t.Fatal("revoke did not continue after refresh committed")
				}
			} else {
				startRevoke()
				select {
				case <-revoked:
				case <-time.After(2 * time.Second):
					t.Fatal("revoke did not reach provider")
				}
				startRefresh()
				select {
				case <-refreshStarted:
					t.Fatal("refresh bypassed revoke lock")
				case <-time.After(100 * time.Millisecond):
				}
			}
			revokeOnce.Do(func() { close(releaseRevoke) })
			refreshOnce.Do(func() { close(releaseRefresh) })
			for _, done := range []chan error{refreshDone, revokeDone} {
				select {
				case err := <-done:
					if done == refreshDone && !refreshFirst {
						if err == nil {
							t.Error("expected refresh to fail after revocation")
						}
					} else if err != nil {
						t.Fatal(err)
					}
				case <-time.After(2 * time.Second):
					t.Fatal("worker did not finish")
				}
			}
			row, err := mysql.OauthTokenByID(context.Background(), dbh, saved.ID)
			if err != nil {
				t.Fatal(err)
			}
			if !row.RefreshTokenExpiresAt.Valid {
				t.Error("revocation marker was lost")
			}
			if refreshFirst && (row.RefreshToken != "NEW_RT" || row.AccessToken != "NEW_AT" || row.RefreshTokenHash != mysql.NewRefreshTokenHash(params.ClientID, "NEW_RT") || row.AccessTokenHash != mysql.NewAccessTokenHash(params.ClientID, "NEW_AT")) {
				t.Error("revoke overwrote the committed token rotation")
			}
		})
	}
}

func TestProviderErrorCounterPreservesConcurrentRevocation(t *testing.T) {
	tr := oauthproxy.NewTokenRequester(dbh, RevokeTestProvider{})
	params := providers.TokenRequestParams{ClientID: "ERROR_COUNTER", ClientSecret: "SECRET", RefreshToken: "ERROR_RT"}
	saved, err := tr.SaveAuthorizationToken(dbh, &oauthproxy.Token{
		Token: &oauth2.Token{AccessToken: "ERROR_AT", RefreshToken: params.RefreshToken, TokenType: "Bearer", Expiry: time.Now().Add(time.Hour)},
		Raw:   map[string]json.RawMessage{},
	}, params, nil)
	if err != nil {
		t.Fatal(err)
	}
	// A failed refresh has released its transaction. Revoke then marks the
	// row before the refresh worker increments its error counter using saved.
	if err := mysql.ExpireRefreshTokenByID(context.Background(), dbh, saved.ID, time.Now()); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		stale := saved
		if err := tr.IncrementNrOfSubsequentProviderErrors(dbh, &stale); err != nil {
			t.Fatal(err)
		}
	}
	row, err := mysql.OauthTokenByID(context.Background(), dbh, saved.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !row.RefreshTokenExpiresAt.Valid {
		t.Error("error counter update undid concurrent revocation")
	}
	if row.NrOfSubsequentProviderErrors != 2 {
		t.Errorf("expected both error increments to be preserved, got %d", row.NrOfSubsequentProviderErrors)
	}
}
