package oauthproxy_test

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	proto "github.com/gogo/protobuf/proto"
	"github.com/golang/snappy"
	"github.com/grafana/loki/v3/pkg/logproto"
	oauthproxy "github.com/omniboost/oauth-proxy"
	"github.com/omniboost/oauth-proxy/providers"
	"golang.org/x/oauth2"
)

// secretEvents starts a fake loki that collects the secret read/write events.
// Each event is the structured metadata plus the operation label.
func secretEvents(t *testing.T) (*oauthproxy.Server, chan map[string]string) {
	t.Helper()
	events := make(chan map[string]string, 10)
	loki := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		b, err := snappy.Decode(nil, b)
		if err != nil {
			t.Error(err)
			return
		}
		push := &logproto.PushRequest{}
		if err := proto.Unmarshal(b, push); err != nil {
			t.Error(err)
			return
		}
		for _, s := range push.Streams {
			operation := ""
			switch s.Labels {
			case `{service="oauth-proxy", event="secret", operation="read"}`:
				operation = "read"
			case `{service="oauth-proxy", event="secret", operation="write"}`:
				operation = "write"
			default:
				continue
			}
			for _, e := range s.Entries {
				m := map[string]string{"operation": operation}
				for _, l := range e.StructuredMetadata {
					m[l.Name] = l.Value
				}
				events <- m
			}
		}
	}))
	t.Cleanup(loki.Close)

	prevURL := oauthproxy.GRAFANA_LOKI_URL
	oauthproxy.GRAFANA_LOKI_URL = loki.URL
	t.Cleanup(func() { oauthproxy.GRAFANA_LOKI_URL = prevURL })

	srv := &oauthproxy.Server{}
	srv.SetClient(srv.NewClient())
	return srv, events
}

func expectSecretEvent(t *testing.T, events chan map[string]string, want map[string]string) {
	t.Helper()
	select {
	case got := <-events:
		for k, v := range want {
			if got[k] != v {
				t.Errorf("%s: expected %q, got %q (%v)", k, v, got[k], got)
			}
		}
		for _, k := range []string{"client_id", "token_id", "expires_at", "refresh_token_hash", "access_token_hash"} {
			if _, ok := got[k]; ok {
				t.Errorf("unexpected metadata %s", k)
			}
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("no event received, expected %v", want)
	}
}

func expectNoSecretEvent(t *testing.T, events chan map[string]string) {
	t.Helper()
	select {
	case got := <-events:
		t.Errorf("unexpected event: %v", got)
	case <-time.After(500 * time.Millisecond):
	}
}

func TestSecretSavedEventPushedToGrafana(t *testing.T) {
	srv, events := secretEvents(t)

	tr := oauthproxy.NewTokenRequester(dbh, NewMockProvider())
	params := providers.TokenRequestParams{
		ClientID:     "GRAFANA",
		ClientSecret: "GRAFANA",
		RefreshToken: "GRAFANA_RT",
	}
	save := func(accessToken, refreshToken string) {
		batch := oauthproxy.NewGrafanaEvents()
		token := &oauthproxy.Token{
			Token: &oauth2.Token{
				AccessToken:  accessToken,
				RefreshToken: refreshToken,
				Expiry:       time.Now().Add(time.Hour),
				TokenType:    "Bearer",
			},
			Raw: map[string]json.RawMessage{},
		}
		if _, err := tr.SaveAuthorizationToken(dbh, token, params, batch); err != nil {
			t.Fatal(err)
		}

		if err := srv.PushEventsToGrafana(batch); err != nil {
			t.Fatal(err)
		}
	}

	// new row
	save("AT1", "GRAFANA_RT")
	expectSecretEvent(t, events, map[string]string{"operation": "write", "app": "TEST", "refresh_token_changed": "true", "access_token_changed": "true"})

	// nothing changed: no event
	save("AT1", "GRAFANA_RT")
	expectNoSecretEvent(t, events)

	// only access token changed
	save("AT2", "GRAFANA_RT")
	expectSecretEvent(t, events, map[string]string{"operation": "write", "refresh_token_changed": "false", "access_token_changed": "true"})

	// refresh token rotated
	save("AT3", "GRAFANA_RT2")
	expectSecretEvent(t, events, map[string]string{"operation": "write", "refresh_token_changed": "true", "access_token_changed": "true"})
}

func TestSecretReadEventPushedToGrafana(t *testing.T) {
	srv, events := secretEvents(t)

	provider := NewRandomProvider()
	tr := oauthproxy.NewTokenRequester(dbh, provider)
	tr.Start()
	params := providers.TokenRequestParams{
		ClientID:     "GRAFANA_READ",
		ClientSecret: "GRAFANA_READ",
		RefreshToken: "GRAFANA_READ_RT",
	}
	request := func() {
		t.Helper()
		batch := oauthproxy.NewGrafanaEvents()
		if _, err := tr.Request(params, batch, nil); err != nil {
			t.Fatal(err)
		}
		if err := srv.PushEventsToGrafana(batch); err != nil {
			t.Fatal(err)
		}
	}

	// expired token: one read (the lookup while saving isn't counted) and a
	// write of the new token
	_, err := tr.SaveAuthorizationToken(dbh, &oauthproxy.Token{
		Token: &oauth2.Token{
			AccessToken:  "GRAFANA_READ_AT",
			RefreshToken: "GRAFANA_READ_RT",
			Expiry:       time.Now().Add(-time.Hour),
			TokenType:    "Bearer",
		},
		Raw: map[string]json.RawMessage{},
	}, params, nil)
	if err != nil {
		t.Fatal(err)
	}
	request()
	expectSecretEvent(t, events, map[string]string{"operation": "read", "app": "RANDOM", "grant_type": "authorization_code"})
	expectSecretEvent(t, events, map[string]string{"operation": "write", "app": "RANDOM"})
	expectNoSecretEvent(t, events)

	// valid token: one read, nothing written
	request()
	expectSecretEvent(t, events, map[string]string{"operation": "read", "app": "RANDOM", "grant_type": "authorization_code"})
	expectNoSecretEvent(t, events)
}

func TestSecretRevokeEventsPushedToGrafana(t *testing.T) {
	srv, events := secretEvents(t)

	revokeEndpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer revokeEndpoint.Close()
	prov := RevokeTestProvider{revokeURL: revokeEndpoint.URL}

	tr := oauthproxy.NewTokenRequester(dbh, prov)
	rv := oauthproxy.NewTokenRevoker(dbh, prov)
	rv.Start()

	save := func(clientID string) {
		t.Helper()
		params := providers.TokenRequestParams{
			ClientID:     clientID,
			ClientSecret: clientID + "_SECRET",
			RefreshToken: clientID + "_RT",
		}
		_, err := tr.SaveAuthorizationToken(dbh, &oauthproxy.Token{
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
	}
	revoke := func(clientID, token, hint string) {
		t.Helper()
		form := url.Values{"token": {token}, "token_type_hint": {hint}, "client_id": {clientID}, "client_secret": {clientID + "_SECRET"}}
		r := httptest.NewRequest(http.MethodPost, prov.RevokeRoute(), strings.NewReader(form.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rrp, err := srv.GetTokenRevokeParamsFromRequest(r)
		if err != nil {
			t.Fatal(err)
		}
		batch := oauthproxy.NewGrafanaEvents()
		resp, err := rv.Revoke(rrp, batch, nil)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if err := srv.PushEventsToGrafana(batch); err != nil {
			t.Fatal(err)
		}
	}

	// refresh token: the row is read and marked as revoked
	save("GRAFANA_REVOKE_RT")
	revoke("GRAFANA_REVOKE_RT", "GRAFANA_REVOKE_RT_RT", "refresh_token")
	expectSecretEvent(t, events, map[string]string{"operation": "read", "app": "REVOKE"})
	expectSecretEvent(t, events, map[string]string{"operation": "write", "app": "REVOKE"})
	expectNoSecretEvent(t, events)

	// access token: only marked as expired, the row isn't read
	save("GRAFANA_REVOKE_AT")
	revoke("GRAFANA_REVOKE_AT", "GRAFANA_REVOKE_AT_AT", "access_token")
	expectSecretEvent(t, events, map[string]string{"operation": "write", "app": "REVOKE"})
	expectNoSecretEvent(t, events)
}

func TestSecretReadEventUnknownToken(t *testing.T) {
	srv, events := secretEvents(t)

	provider := NewRandomProvider()
	tr := oauthproxy.NewTokenRequester(dbh, provider)
	tr.Start()

	// unknown refresh token: the lookup is still a read, followed by a write of
	// the new token row
	params := providers.TokenRequestParams{
		ClientID:     "GRAFANA_UNKNOWN",
		ClientSecret: "GRAFANA_UNKNOWN",
		RefreshToken: "GRAFANA_UNKNOWN_RT",
	}
	batch := oauthproxy.NewGrafanaEvents()
	if _, err := tr.Request(params, batch, nil); err != nil {
		t.Fatal(err)
	}
	if err := srv.PushEventsToGrafana(batch); err != nil {
		t.Fatal(err)
	}
	expectSecretEvent(t, events, map[string]string{"operation": "read", "app": "RANDOM"})
	expectSecretEvent(t, events, map[string]string{"operation": "write", "app": "RANDOM"})
	expectNoSecretEvent(t, events)
}

func TestSecretSavedEventOnFailure(t *testing.T) {
	srv, events := secretEvents(t)

	tr := oauthproxy.NewTokenRequester(dbh, NewMockProvider())
	save := func(refreshToken, newRefreshToken string, batch *oauthproxy.GrafanaEvents) error {
		params := providers.TokenRequestParams{
			ClientID:     "GRAFANA_FAIL",
			ClientSecret: "GRAFANA_FAIL",
			RefreshToken: refreshToken,
		}
		_, err := tr.SaveAuthorizationToken(dbh, &oauthproxy.Token{
			Token: &oauth2.Token{
				AccessToken:  "GRAFANA_FAIL_AT",
				RefreshToken: newRefreshToken,
				Expiry:       time.Now().Add(time.Hour),
				TokenType:    "Bearer",
			},
			Raw: map[string]json.RawMessage{},
		}, params, batch)
		return err
	}

	if err := save("GRAFANA_FAIL_RT1", "GRAFANA_FAIL_DUP", nil); err != nil {
		t.Fatal(err)
	}

	// a new row with the same refresh token violates the unique key: the
	// attempt is still counted as a write
	batch := oauthproxy.NewGrafanaEvents()
	if err := save("GRAFANA_FAIL_RT2", "GRAFANA_FAIL_DUP", batch); err == nil {
		t.Fatal("expected duplicate key error")
	}
	if err := srv.PushEventsToGrafana(batch); err != nil {
		t.Fatal(err)
	}
	expectSecretEvent(t, events, map[string]string{"operation": "write", "app": "TEST"})
}
