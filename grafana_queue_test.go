package oauthproxy

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/felixge/httpsnoop"
	proto "github.com/gogo/protobuf/proto"
	"github.com/golang/snappy"
	"github.com/grafana/loki/v3/pkg/logproto"
	"github.com/omniboost/oauth-proxy/mysql"
	"golang.org/x/oauth2"
)

func setupGrafanaEventsTest(t *testing.T, limit int, url string) *GrafanaEvents {
	t.Helper()
	oldURL := GRAFANA_LOKI_URL
	GRAFANA_LOKI_URL = url
	t.Cleanup(func() { GRAFANA_LOKI_URL = oldURL })
	return &GrafanaEvents{limit: limit}
}

func TestQueueGrafanaEventDropsWhenFull(t *testing.T) {
	const limit = 10
	events := setupGrafanaEventsTest(t, limit, "http://loki.invalid/push")
	for i := 0; i < 1000; i++ {
		events.QueueTokenSavedEvent(mysql.OauthToken{App: "TEST"}, true, true, true)
	}
	if got := len(events.events); got != limit {
		t.Fatalf("expected %d events, got %d", limit, got)
	}
}

func TestQueueGrafanaEventSkipped(t *testing.T) {
	events := setupGrafanaEventsTest(t, 10, "http://loki.invalid/push")

	// nothing changed
	events.QueueTokenSavedEvent(mysql.OauthToken{App: "TEST"}, false, false, false)

	// grafana not configured
	GRAFANA_LOKI_URL = ""
	events.QueueTokenSavedEvent(mysql.OauthToken{App: "TEST"}, true, true, true)
	events.QueueRequestLog(httptest.NewRequest(http.MethodPost, "/TEST/oauth2/token", nil), httpsnoop.Metrics{Code: http.StatusOK})

	if got := len(events.events); got != 0 {
		t.Fatalf("expected no events, got %d", got)
	}
}

func TestPushEventsToGrafanaGroupsStreams(t *testing.T) {
	pushes := make(chan *logproto.PushRequest, 10)
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
		pushes <- push
	}))
	defer loki.Close()
	events := setupGrafanaEventsTest(t, 10, loki.URL)

	s := &Server{}
	s.SetClient(s.NewClient())

	// nothing queued: no push
	if err := s.PushEventsToGrafana(events); err != nil {
		t.Fatal(err)
	}

	r := httptest.NewRequest(http.MethodPost, "/TEST/oauth2/token", nil)
	events.QueueTokenSavedEvent(mysql.OauthToken{App: "A"}, true, true, true)
	events.QueueTokenSavedEvent(mysql.OauthToken{App: "B"}, false, true, false)
	events.QueueRequestLog(r, httpsnoop.Metrics{Code: http.StatusBadRequest})
	if err := s.PushEventsToGrafana(events); err != nil {
		t.Fatal(err)
	}

	select {
	case push := <-pushes:
		if len(push.Streams) != 2 {
			t.Fatalf("expected 2 streams, got %d", len(push.Streams))
		}
		tokens, requests := push.Streams[0], push.Streams[1]
		if tokens.Labels != `{service="oauth-proxy", event="token_saved"}` || len(tokens.Entries) != 2 {
			t.Errorf("unexpected token stream: %s with %d entries", tokens.Labels, len(tokens.Entries))
		}
		if tokens.Entries[0].Line != "token saved for app A" || tokens.Entries[1].Line != "token saved for app B" {
			t.Errorf("token events out of order: %q, %q", tokens.Entries[0].Line, tokens.Entries[1].Line)
		}
		if requests.Labels != `{service="oauth-proxy"}` || len(requests.Entries) != 1 {
			t.Errorf("unexpected request stream: %s with %d entries", requests.Labels, len(requests.Entries))
		}
		if requests.Entries[0].StructuredMetadata[0].Value != "error" {
			t.Errorf("expected level error for status 400, got %s", requests.Entries[0].StructuredMetadata[0].Value)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no push received")
	}

	if err := s.PushEventsToGrafana(events); err != nil {
		t.Fatal(err)
	}
	select {
	case push := <-pushes:
		t.Fatalf("unexpected extra push: %v", push)
	default:
	}
}

type grafanaTestProvider struct{}

func (grafanaTestProvider) Name() string  { return "TEST" }
func (grafanaTestProvider) Route() string { return "/TEST/oauth2/token" }

func TestGrafanaEventsStayWithTheirRequest(t *testing.T) {
	pushes := make(chan *logproto.PushRequest, 2)
	release := make(chan struct{}, 2)
	// Unblock the test server even when an assertion fails.
	defer close(release)
	loki := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
			return
		}
		body, err = snappy.Decode(nil, body)
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
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	// Release blocked pushes before Close waits for their handlers.
	t.Cleanup(loki.Close)
	setupGrafanaEventsTest(t, 10, loki.URL)
	provider := grafanaTestProvider{}
	tr := NewTokenRequester(nil, provider)
	s := &Server{client: &http.Client{Timeout: 2 * time.Second}, tokenRequesters: map[string]*TokenRequester{provider.Name(): tr}}
	handler := s.NewProviderTokenHandler(provider)
	done := make(chan string, 2)
	for _, id := range []string{"A", "B"} {
		go func() {
			r := httptest.NewRequest(http.MethodPost, "/"+id, strings.NewReader("client_id="+id))
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, r)
			if w.Code != http.StatusOK {
				t.Errorf("request %s: status %d", id, w.Code)
			}
			done <- id
		}()
	}

	// Receive both requests at the worker boundary and queue both token events
	// before either handler finishes. A global queue would mix these batches.
	requests := map[string]TokenRequest{}
	for range 2 {
		select {
		case req := <-tr.requests:
			requests[req.params.ClientID] = req
			req.events.QueueTokenSavedEvent(mysql.OauthToken{App: req.params.ClientID}, true, true, true)
		case <-time.After(2 * time.Second):
			t.Fatal("token request did not reach worker")
		}
	}
	for _, id := range []string{"A", "B"} {
		tr.handleResults(requests[id], &Token{Token: &oauth2.Token{AccessToken: id, Expiry: time.Now().Add(time.Hour)}, Raw: map[string]json.RawMessage{}}, nil)
		select {
		case push := <-pushes:
			if len(push.Streams) != 2 {
				t.Fatalf("request %s: expected two streams, got %d", id, len(push.Streams))
			}
			for _, stream := range push.Streams {
				want := "/" + id
				if stream.Labels == `{service="oauth-proxy", event="token_saved"}` {
					want = "token saved for app " + id
				}
				if len(stream.Entries) != 1 || stream.Entries[0].Line != want {
					t.Fatalf("request %s received another request's events: %v", id, stream.Entries)
				}
			}
		case <-time.After(2 * time.Second):
			t.Fatal("no push received")
		}
		select {
		case returned := <-done:
			t.Fatalf("request %s returned before Loki finished", returned)
		default:
		}
	}
	// Both requests have their own in-flight push and wait for its completion.
	for range 2 {
		release <- struct{}{}
	}
	for range 2 {
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Fatal("handler did not return after Loki completed")
		}
	}
}
