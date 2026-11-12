package oauthproxy

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/getsentry/sentry-go"
	proto "github.com/gogo/protobuf/proto"
	"github.com/golang/snappy"
	"github.com/grafana/loki/v3/pkg/logproto"
)

type revokeHandlerTestProvider struct {
	revokeURL string
}

func (p revokeHandlerTestProvider) Name() string        { return "REVOKE_HANDLER" }
func (p revokeHandlerTestProvider) RevokeRoute() string { return "/REVOKE_HANDLER/oauth2/revoke" }
func (p revokeHandlerTestProvider) RevokeURL() string   { return p.revokeURL }

func TestRevokeHandlerPassesProviderStatusCode(t *testing.T) {
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"error":"invalid_client"}`))
	}))
	defer provider.Close()
	prov := revokeHandlerTestProvider{revokeURL: provider.URL}

	// access token rejected by the provider: the revoker doesn't touch the
	// database
	rv := NewTokenRevoker(nil, prov)
	rv.Start()
	s := &Server{tokenRevokers: map[string]*TokenRevoker{prov.Name(): rv}}

	form := url.Values{"token": {"TOKEN"}, "token_type_hint": {"access_token"}}
	r := httptest.NewRequest(http.MethodPost, prov.RevokeRoute(), strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	s.NewProviderRevokeHandler(prov).ServeHTTP(w, r)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected provider status 400, got %d", w.Code)
	}
	if body := w.Body.String(); body != `{"error":"invalid_client"}` {
		t.Errorf("expected provider body, got %q", body)
	}
}

func TestRevokeTimeout(t *testing.T) {
	release := make(chan struct{})
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-release
	}))
	// unblock the provider before Close waits for its handler
	defer provider.Close()
	defer close(release)
	prov := revokeHandlerTestProvider{revokeURL: provider.URL}

	oldTimeout := tokenRevokeTimeout
	tokenRevokeTimeout = 100 * time.Millisecond
	defer func() { tokenRevokeTimeout = oldTimeout }()

	rv := NewTokenRevoker(nil, prov)
	rv.Start()

	r := httptest.NewRequest(http.MethodPost, prov.RevokeRoute(), nil)
	done := make(chan error, 1)
	go func() {
		_, err := rv.Revoke(TokenRevokeParams{Token: "TOKEN", TokenTypeHint: "access_token", Request: r}, nil, nil)
		done <- err
	}()

	select {
	case err := <-done:
		if err == nil {
			t.Error("expected timeout error")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("revoke didn't time out")
	}
}

func TestRevokeHandlerLogging(t *testing.T) {
	pushes := make(chan *logproto.PushRequest, 1)
	loki := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		body, err := snappy.Decode(nil, body)
		if err != nil {
			t.Error(err)
			return
		}
		push := &logproto.PushRequest{}
		if err := proto.Unmarshal(body, push); err != nil {
			t.Error(err)
			return
		}
		pushes <- push
	}))
	defer loki.Close()
	setupGrafanaEventsTest(t, 10, loki.URL)

	transport := &sentryTestTransport{}
	if err := sentry.Init(sentry.ClientOptions{Dsn: "https://public@sentry.invalid/1", Transport: transport}); err != nil {
		t.Fatal(err)
	}
	defer sentry.CurrentHub().BindClient(nil)

	// no token revoker for the provider: revoking fails
	prov := revokeHandlerTestProvider{}
	s := &Server{client: &http.Client{Timeout: time.Second}, tokenRevokers: map[string]*TokenRevoker{}}

	form := url.Values{"token": {"SECRET"}, "token_type_hint": {"refresh_token"}, "client_id": {"A"}, "client_secret": {"SECRET"}}
	r := httptest.NewRequest(http.MethodPost, prov.RevokeRoute(), strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	s.NewProviderRevokeHandler(prov).ServeHTTP(httptest.NewRecorder(), r)

	transport.mu.Lock()
	if len(transport.events) != 1 {
		t.Fatalf("expected 1 sentry event, got %d", len(transport.events))
	}
	if transport.unflushed != 0 {
		t.Error("expected sentry event to be flushed before the handler returned")
	}
	e := transport.events[0]
	if e.Tags["Provider"] != prov.Name() || e.Tags["ClientID"] != "A" || e.Tags["TokenTypeHint"] != "refresh_token" {
		t.Errorf("unexpected sentry tags: %v", e.Tags)
	}
	for k, v := range e.Tags {
		if strings.Contains(v, "SECRET") {
			t.Errorf("secret sent to sentry in tag %s", k)
		}
	}
	for k, v := range e.Extra {
		if strings.Contains(fmt.Sprint(v), "SECRET") {
			t.Errorf("secret sent to sentry in extra %s", k)
		}
	}
	transport.mu.Unlock()

	select {
	case push := <-pushes:
		if len(push.Streams) != 1 || push.Streams[0].Labels != `{service="oauth-proxy"}` {
			t.Fatalf("unexpected grafana push: %v", push.Streams)
		}
		entry := push.Streams[0].Entries[0]
		if entry.Line != prov.RevokeRoute() {
			t.Errorf("expected request log for %s, got %s", prov.RevokeRoute(), entry.Line)
		}
		if entry.StructuredMetadata[0].Value != "error" {
			t.Errorf("expected level error, got %s", entry.StructuredMetadata[0].Value)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no grafana push received")
	}
}
