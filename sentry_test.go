package oauthproxy

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/getsentry/sentry-go"
)

// sentryTestTransport records sent events and whether they were flushed
type sentryTestTransport struct {
	mu        sync.Mutex
	events    []*sentry.Event
	unflushed int
}

func (t *sentryTestTransport) Configure(sentry.ClientOptions) {}
func (t *sentryTestTransport) Close()                         {}

func (t *sentryTestTransport) SendEvent(event *sentry.Event) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.events = append(t.events, event)
	t.unflushed++
}

func (t *sentryTestTransport) Flush(time.Duration) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.unflushed = 0
	return true
}

func (t *sentryTestTransport) FlushWithContext(context.Context) bool {
	return t.Flush(0)
}

func TestSentryScopePerRequest(t *testing.T) {
	transport := &sentryTestTransport{}
	if err := sentry.Init(sentry.ClientOptions{Dsn: "https://public@sentry.invalid/1", Transport: transport}); err != nil {
		t.Fatal(err)
	}
	defer sentry.CurrentHub().BindClient(nil)

	// no token requester for the provider: the token request fails after the
	// sentry tags are set
	provider := grafanaTestProvider{}
	s := &Server{client: &http.Client{Timeout: time.Second}, tokenRequesters: map[string]*TokenRequester{}}
	handler := s.NewProviderTokenHandler(provider)

	r := httptest.NewRequest(http.MethodPost, "/TEST/oauth2/token", strings.NewReader("client_id=A&client_secret=SECRET&refresh_token=SECRET&code=SECRET&code_verifier=SECRET"))
	handler.ServeHTTP(httptest.NewRecorder(), r)

	// invalid content type: fails before the sentry tags are set
	r = httptest.NewRequest(http.MethodPost, "/TEST/oauth2/token", strings.NewReader(""))
	r.Header.Set("Content-Type", "a/b; =")
	handler.ServeHTTP(httptest.NewRecorder(), r)

	transport.mu.Lock()
	defer transport.mu.Unlock()
	if len(transport.events) != 2 {
		t.Fatalf("expected 2 events, got %d", len(transport.events))
	}
	if transport.unflushed != 0 {
		t.Errorf("expected all events to be flushed before the handler returned, %d unflushed", transport.unflushed)
	}
	if got := transport.events[0].Tags["ClientID"]; got != "A" {
		t.Errorf("expected ClientID tag A on first event, got %q", got)
	}
	for _, e := range transport.events {
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
	}
	for _, tag := range []string{"Provider", "ClientID", "RefreshToken"} {
		if got, ok := transport.events[1].Tags[tag]; ok {
			t.Errorf("tag %s leaked into the next request: %q", tag, got)
		}
	}
}
