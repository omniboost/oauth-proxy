package oauthproxy_test

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	proto "github.com/gogo/protobuf/proto"
	"github.com/golang/snappy"
	"github.com/grafana/loki/v3/pkg/logproto"
	oauthproxy "github.com/omniboost/oauth-proxy"
	"github.com/omniboost/oauth-proxy/providers"
	"golang.org/x/oauth2"
)

func TestTokenSavedEventPushedToGrafana(t *testing.T) {
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
			if s.Labels != `{service="oauth-proxy", event="token_saved"}` {
				continue
			}
			for _, e := range s.Entries {
				m := map[string]string{}
				for _, l := range e.StructuredMetadata {
					m[l.Name] = l.Value
				}
				events <- m
			}
		}
	}))
	defer loki.Close()

	prevURL := oauthproxy.GRAFANA_LOKI_URL
	oauthproxy.GRAFANA_LOKI_URL = loki.URL
	defer func() { oauthproxy.GRAFANA_LOKI_URL = prevURL }()

	srv := &oauthproxy.Server{}
	srv.SetClient(srv.NewClient())

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
	expect := func(want map[string]string) {
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
			t.Fatal("no event received")
		}
	}
	expectNone := func() {
		t.Helper()
		select {
		case got := <-events:
			t.Errorf("unexpected event: %v", got)
		case <-time.After(500 * time.Millisecond):
		}
	}

	// new row
	save("AT1", "GRAFANA_RT")
	expect(map[string]string{"app": "TEST", "new_row": "true", "refresh_token_changed": "true", "access_token_changed": "true"})

	// nothing changed: no event
	save("AT1", "GRAFANA_RT")
	expectNone()

	// only access token changed
	save("AT2", "GRAFANA_RT")
	expect(map[string]string{"new_row": "false", "refresh_token_changed": "false", "access_token_changed": "true"})

	// refresh token rotated
	save("AT3", "GRAFANA_RT2")
	expect(map[string]string{"new_row": "false", "refresh_token_changed": "true", "access_token_changed": "true"})
}
