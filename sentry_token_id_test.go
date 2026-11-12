package oauthproxy_test

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/getsentry/sentry-go"
	oauthproxy "github.com/omniboost/oauth-proxy"
	"github.com/omniboost/oauth-proxy/providers"
	"golang.org/x/oauth2"
)

type FailingProvider struct{}

func (FailingProvider) Name() string  { return "FAILING" }
func (FailingProvider) Route() string { return "/FAILING/oauth2/token" }

func (p FailingProvider) Exchange(ctx context.Context, params providers.TokenRequestParams, opts ...oauth2.AuthCodeOption) (*oauth2.Token, error) {
	return p.TokenSourceAuthorizationCode(ctx, params).Token()
}

func (FailingProvider) TokenSourceAuthorizationCode(ctx context.Context, params providers.TokenRequestParams) oauth2.TokenSource {
	return FailingTokenSource{}
}

type FailingTokenSource struct{}

func (FailingTokenSource) Token() (*oauth2.Token, error) {
	return nil, errors.New("invalid_grant")
}

func TestSentryTokenIDOnProviderError(t *testing.T) {
	tr := oauthproxy.NewTokenRequester(dbh, FailingProvider{})
	tr.Start()

	params := providers.TokenRequestParams{
		ClientID:     "SENTRY",
		ClientSecret: "SENTRY_SECRET",
		RefreshToken: "SENTRY_REFRESH_TOKEN",
	}

	// expired token, so the requester has to refresh it at the provider
	dbToken, err := tr.SaveAuthorizationToken(dbh, &oauthproxy.Token{
		Token: &oauth2.Token{
			AccessToken:  "SENTRY_ACCESS_TOKEN",
			RefreshToken: "SENTRY_REFRESH_TOKEN",
			Expiry:       time.Now().Add(-time.Hour),
			TokenType:    "Bearer",
		},
		Raw: map[string]json.RawMessage{},
	}, params, nil)
	if err != nil {
		t.Fatal(err)
	}

	transport := &sentry.MockTransport{}
	client, err := sentry.NewClient(sentry.ClientOptions{Dsn: "https://public@sentry.invalid/1", Transport: transport})
	if err != nil {
		t.Fatal(err)
	}
	hub := sentry.NewHub(client, sentry.NewScope())

	_, err = tr.Request(params, nil, hub)
	if err == nil {
		t.Fatal("expected provider error")
	}
	if strings.Contains(err.Error(), "SENTRY_REFRESH_TOKEN") {
		t.Errorf("refresh token in error message: %s", err)
	}

	hub.CaptureException(err)
	events := transport.Events()
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	if got, want := events[0].Tags["TokenID"], strconv.Itoa(dbToken.ID); got != want {
		t.Errorf("expected TokenID tag %s, got %q", want, got)
	}
	for _, exception := range events[0].Exception {
		if strings.Contains(exception.Value, "SENTRY_") {
			t.Errorf("secret in sentry exception: %s", exception.Value)
		}
	}
}
