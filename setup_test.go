package oauthproxy_test

import (
	"context"
	"database/sql"
	"log"
	"os"
	"testing"
	"time"

	_ "github.com/go-sql-driver/mysql"
	"github.com/omniboost/oauth-proxy/providers"
	"github.com/xo/dburl"
	"golang.org/x/oauth2"
)

var (
	dbh *sql.DB
)

func TestMain(m *testing.M) {
	var err error

	// db.SetLogger(fmt.Printf)
	dbh, err = dburl.Open(os.Getenv("DATABASE_URL"))
	if err != nil {
		log.Fatal(err)
	}
	dbh.SetMaxOpenConns(1)

	q, err := os.ReadFile("assets/drop.mysql.sql")
	if err != nil {
		log.Fatal(err)
	}

	_, err = dbh.Exec(string(q))
	if err != nil {
		log.Fatal(err)
	}

	q, err = os.ReadFile("assets/empty.mysql.sql")
	if err != nil {
		log.Fatal(err)
	}

	_, err = dbh.Exec(string(q))
	if err != nil {
		log.Fatal(err)
	}

	m.Run()
}

type MockProvider struct {
	name     string
	authURL  string
	tokenURL string
}

func NewMockProvider() *MockProvider {
	return &MockProvider{}
}

func (v MockProvider) Name() string {
	return "TEST"
}

func (v MockProvider) Route() string {
	return "/TEST/oauth2/token"
}

func (v MockProvider) Exchange(ctx context.Context, params providers.TokenRequestParams, opts ...oauth2.AuthCodeOption) (*oauth2.Token, error) {
	return v.TokenSource(ctx, params).Token()
}

func (v MockProvider) TokenSource(ctx context.Context, params providers.TokenRequestParams) oauth2.TokenSource {
	return MockTokenSource{}
}

type MockTokenSource struct{}

func (ts MockTokenSource) Token() (*oauth2.Token, error) {
	return &oauth2.Token{
		AccessToken:  "MOCK",
		RefreshToken: "MOCK",
		Expiry:       time.Time{},
		ExpiresIn:    0,
	}, nil
}
