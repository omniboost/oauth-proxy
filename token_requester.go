package oauthproxy

import (
	"context"
	"database/sql"
	"log"

	"bitbucket.org/tim_online/oauth-proxy/db"
	"bitbucket.org/tim_online/oauth-proxy/providers"
	"golang.org/x/oauth2"
)

func NewTokenRequester(db *sql.DB, provider providers.Provider) *TokenRequester {
	// Create a new context
	ctx := context.Background()
	// Create a new context, with its cancellation function
	// from the original context
	// ctx, cancel := context.WithCancel(ctx)

	return &TokenRequester{
		db:       db,
		provider: provider,
		ctx:      ctx,
	}
}

type TokenRequester struct {
	db         *sql.DB
	provider   providers.Provider
	requests   chan providers.TokenRequestParams
	tokenChans []chan *oauth2.Token
	errChans   []chan error
	ctx        context.Context
}

func (tr *TokenRequester) Start() {
	go tr.Listen()
}

func (tr *TokenRequester) Listen() {
	for {
		select {
		case <-tr.requests:
			// If we receive a message after 2 seconds
			// that means the request has been processed
			// We then write this as the response
			log.Println("Request received")
		case <-tr.ctx.Done():
			return
		}
	}
}

func (tr *TokenRequester) Stop() {
	// ??
}

func (tr *TokenRequester) Request(params providers.TokenRequestParams) (*oauth2.Token, error) {
	dbToken, err := db.OauthTokenByAppClientIDClientSecretRefreshToken(tr.db, tr.provider.Name(),
		params.ClientID, params.ClientSecret, params.RefreshToken)
	if err == sql.ErrNoRows {
		// no results in db: request new token
		tokenChan, errChan := tr.AddRequest(params)

		// block on both channels
		token := <-tokenChan
		err := <-errChan
		return token, err
	} else if err != nil {
		// error requesting token from db
		return nil, err
	}

	// no error, retrieved token from database
	token := &oauth2.Token{
		AccessToken:  dbToken.AccessToken,
		RefreshToken: dbToken.RefreshToken,
		TokenType:    dbToken.Type,
		Expiry:       dbToken.ExpiresAt.Time,
	}

	// check if token is still valid
	if token.Valid() {
		return token, nil
	}

	// token is not valid anymore
	tokenChan, errChan := tr.AddRequest(params)
	// block on both channels
	token = <-tokenChan
	err = <-errChan
	return token, err
}

func (tr *TokenRequester) AddRequest(params providers.TokenRequestParams) (chan *oauth2.Token, chan error) {
	tr.requests <- params
	tokenChan := make(chan *oauth2.Token, 1)
	tr.tokenChans = append(tr.tokenChans, tokenChan)
	errChan := make(chan error, 1)
	tr.errChans = append(tr.errChans, errChan)
	return tokenChan, errChan
}
