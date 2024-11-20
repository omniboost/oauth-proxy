package main

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"os"
	"time"

	_ "github.com/go-sql-driver/mysql"
	"github.com/omniboost/oauth-proxy/mysql"
	"github.com/omniboost/oauth-proxy/sqlite"
	"github.com/xo/dburl"
	moderncsqlite "modernc.org/sqlite"
)

var (
	sqliteDB *sql.DB
	mysqlDB  *sql.DB
)

func main() {
	// two parameters
	// - sqlite db url
	// mysql db url

	// loop through each sqlite entry, check based on app, client_id,
	// client_secret & refresh_token
	// if not found in mysql, copy to mysql
	// if found in mysql & different -> update

	if len(os.Args) != 3 {
		fmt.Println("Usage: convert-sqlite-to-mysql <sqlite_db_url> <mysql_db_url>")
		os.Exit(1)
	}

	sqliteDBURL := os.Args[1]
	mysqlDBURL := os.Args[2]

	var err error

	sql.Register("moderncsqlite", &moderncsqlite.Driver{})
	// sqlite.SetLogger(fmt.Printf)
	sqliteDB, err = dburl.Open(sqliteDBURL)
	if err != nil {
		log.Fatal(err)
	}
	sqliteDB.SetMaxOpenConns(1)

	// mysql.SetLogger(fmt.Printf)
	mysqlDB, err = dburl.Open(mysqlDBURL)
	if err != nil {
		log.Fatal(err)
	}
	mysqlDB.SetMaxOpenConns(1)

	ids, err := sqlite.AllIDs(context.Background(), sqliteDB)
	if err != nil {
		log.Fatal(err)
	}

	for _, id := range ids {
		ot, err := sqlite.OauthTokenByID(context.Background(), sqliteDB, id)
		if err != nil {
			log.Fatal(err)
		}

		// check if exists in mysql
		mysqlToken, err := mysql.OauthTokenByAppClientIDClientSecretRefreshToken(context.Background(), mysqlDB, ot.App, ot.ClientID, ot.ClientSecret, ot.RefreshToken)
		if err != nil && err != sql.ErrNoRows {
			log.Fatal(err)
		}

		// - if it exists, compare with sqlite token
		// - if the same: skip
		if err == nil {
			same := func() bool {
				if mysqlToken.App != ot.App {
					log.Println("app mismatch")
					return false
				}
				if mysqlToken.ClientID != ot.ClientID {
					log.Println("client id mismatch")
					return false
				}
				if mysqlToken.ClientSecret != ot.ClientSecret {
					log.Println("client secret mismatch")
					return false
				}
				if mysqlToken.RefreshToken != ot.RefreshToken {
					log.Println("refresh token mismatch")
					return false
				}
				if mysqlToken.OriginalRefreshToken != ot.OriginalRefreshToken {
					log.Println("original refresh token mismatch")
					return false
				}
				if mysqlToken.CodeVerifier != ot.CodeVerifier {
					log.Println("code verifier mismatch")
					return false
				}
				if !mysqlToken.ExpiresAt.Time.Equal(ot.ExpiresAt.Time().Round(time.Microsecond)) {
					log.Println("expires at mismatch")
					return false
				}
				if !mysqlToken.CreatedAt.Equal(ot.CreatedAt.Time().Round(time.Microsecond)) {
					log.Println("created at mismatch")
					return false
				}
				if !mysqlToken.UpdatedAt.Equal(ot.UpdatedAt.Time().Round(time.Microsecond)) {
					log.Println("updated at mismatch")
					return false
				}
				return true
			}()
			if same {
				continue
			}
		}

		// check if the id already exists in mysql
		id := ot.ID
		check, err := mysql.OauthTokenByID(context.Background(), mysqlDB, id)
		if err != nil && err != sql.ErrNoRows {
			log.Fatal(err)
		}

		// if the token already exists, use that id
		if mysqlToken != nil {
			log.Printf("using existing id %d", mysqlToken.ID)
    		id = mysqlToken.ID
		}

		// the token doesn't exist, but the id already exists, use a new id
		if mysqlToken == nil && check != nil {
			log.Printf("using new id %d", id)
			id = 0
		}

		// update the existing mysqltoken so the _exists field is set
		expiresAt := sql.NullTime{}
		if ot.ExpiresAt != nil && !ot.ExpiresAt.Time().IsZero() {
			expiresAt = sql.NullTime{Time: ot.ExpiresAt.Time().Round(time.Microsecond), Valid: true}
		}
		refreshTokenExpiresAt := sql.NullTime{}
		if ot.RefreshTokenExpiresAt != nil && !ot.RefreshTokenExpiresAt.Time().IsZero() {
			refreshTokenExpiresAt = sql.NullTime{Time: ot.RefreshTokenExpiresAt.Time().Round(time.Microsecond), Valid: true}
		}
		mysqlToken = &mysql.OauthToken{
			ID:                       id,
			App:                      ot.App,
			Type:                     ot.Type,
			ClientID:                 ot.ClientID,
			ClientSecret:             ot.ClientSecret,
			OriginalRefreshToken:     ot.OriginalRefreshToken,
			RefreshToken:             ot.RefreshToken,
			AccessToken:              ot.AccessToken,
			ExpiresAt:                expiresAt,
			CreatedAt:                ot.CreatedAt.Time().Round(time.Microsecond),
			UpdatedAt:                ot.UpdatedAt.Time().Round(time.Microsecond),
			CodeExchangeResponseBody: ot.CodeExchangeResponseBody,
			CodeVerifier:             ot.CodeVerifier,
			RefreshTokenExpiresAt:    refreshTokenExpiresAt,
		}

		// save update/new token
		err = mysqlToken.Upsert(context.Background(), mysqlDB)
		if err != nil {
			log.Fatal(err)
		}
	}
}
