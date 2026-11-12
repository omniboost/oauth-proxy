package oauthproxy

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
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
		_, err := rv.Revoke(TokenRevokeParams{Token: "TOKEN", TokenTypeHint: "access_token", Request: r})
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
