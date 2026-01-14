package oauthproxy_test

import (
	"context"
	"database/sql"
	"log"
	"os"
	"sync/atomic"
	"testing"
	"time"

	_ "github.com/go-sql-driver/mysql"
	"github.com/omniboost/oauth-proxy/mysql"
	"github.com/omniboost/oauth-proxy/providers"
	"github.com/xo/dburl"
	"golang.org/x/exp/rand"
	"golang.org/x/oauth2"
)

var (
	dbh *sql.DB
)

func TestMain(m *testing.M) {
	var err error

	mysql.SetLogger(log.Printf)
	dbh, err = dburl.Open(os.Getenv("DATABASE_URL"))
	if err != nil {
		log.Fatal(err)
	}
	// dbh.SetMaxOpenConns(1)
	// dbh.SetConnMaxIdleTime(time.Second)
	// dbh.SetConnMaxLifetime(time.Second)

	// set wait timeout
	// dbh.Exec("SET GLOBAL wait_timeout = 5")
	// dbh.Exec("SET autocommit = 0")

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
	return v.TokenSourceAuthorizationCode(ctx, params).Token()
}

func (v MockProvider) TokenSourceAuthorizationCode(ctx context.Context, params providers.TokenRequestParams) oauth2.TokenSource {
	return MockTokenSource{}
}

type MockTokenSource struct{}

func (ts MockTokenSource) Token() (*oauth2.Token, error) {
	return &oauth2.Token{
		AccessToken:  "MOCK",
		RefreshToken: "MOCK",
		Expiry:       time.Now(),
		ExpiresIn:    0,
	}, nil
}

type RandomProvider struct {
	name        string
	tokenSource *RandomTokenSource
}

func NewRandomProvider() *RandomProvider {
	return &RandomProvider{
		tokenSource: &RandomTokenSource{},
	}
}

func (v *RandomProvider) Name() string {
	return "RANDOM"
}

func (v *RandomProvider) Route() string {
	return "/RANDOM/oauth2/token"
}

func (v RandomProvider) Exchange(ctx context.Context, params providers.TokenRequestParams, opts ...oauth2.AuthCodeOption) (*oauth2.Token, error) {
	return v.TokenSourceAuthorizationCode(ctx, params).Token()
}

func (v RandomProvider) TokenSourceAuthorizationCode(ctx context.Context, params providers.TokenRequestParams) oauth2.TokenSource {
	return v.tokenSource
}
func (v RandomProvider) Called() uint64 {
	return v.tokenSource.Called.Load()
}

type RandomTokenSource struct {
	Called atomic.Uint64
}

func (ts *RandomTokenSource) Token() (*oauth2.Token, error) {
	time.Sleep(100 * time.Millisecond)
	ts.Called.Add(1)
	token := RandStringRunes(32)
	return &oauth2.Token{
		AccessToken:  token,
		RefreshToken: token,
		Expiry:       time.Now().Add(time.Hour * 3),
		ExpiresIn:    10800,
	}, nil
}

var letterRunes = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")

func RandStringRunes(n int) string {
	b := make([]rune, n)
	for i := range b {
		b[i] = letterRunes[rand.Intn(len(letterRunes))]
	}
	return string(b)
}
