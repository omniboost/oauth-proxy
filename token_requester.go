package oauthproxy

import (
	"context"
	"database/sql"

	"bitbucket.org/tim_online/oauth-proxy/db"
	"bitbucket.org/tim_online/oauth-proxy/providers"
	"github.com/xo/xoutil"
	"golang.org/x/oauth2"
)

func NewTokenRequester(db *sql.DB, provider providers.Provider) *TokenRequester {
	// Create a new context
	ctx := context.Background()
	// Create a new context, with its cancellation function
	// from the original context
	// ctx, cancel := context.WithCancel(ctx)

	return &TokenRequester{
		db:         db,
		provider:   provider,
		requests:   make(chan providers.TokenRequestParams),
		ctx:        ctx,
		tokenChans: []chan *oauth2.Token{},
		errChans:   []chan error{},
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
		case params := <-tr.requests:
			// received the request, maybe there are more in the queue
			token, err := tr.RetrieveNewToken(params)

			// send result to every request in the queue
			for _, ch := range tr.tokenChans {
				ch <- token
			}
			tr.tokenChans = []chan *oauth2.Token{}

			// Send error to all channels
			for _, ch := range tr.errChans {
				ch <- err
			}

			// Clean channels
			tr.errChans = []chan error{}
		case <-tr.ctx.Done():
			return
		}
	}
}

func (tr *TokenRequester) Stop() {
	// ??
}

func (tr *TokenRequester) Request(params providers.TokenRequestParams) (*oauth2.Token, error) {
	dbToken, err := db.OauthTokenByAppClientIDClientSecretOriginalRefreshToken(tr.db, tr.provider.Name(),
		params.ClientID, params.ClientSecret, params.RefreshToken)
	if err == sql.ErrNoRows {
		// no results in db: request new token
		token, err := tr.FetchNewToken(params)
		if err != nil {
			return token, err
		}

		dbToken = &db.OauthToken{
			App:                  tr.provider.Name(),
			Type:                 token.Type(),
			ClientID:             params.ClientID,
			ClientSecret:         params.ClientSecret,
			OriginalRefreshToken: params.RefreshToken,
			RefreshToken:         token.RefreshToken,
			AccessToken:          token.AccessToken,
			ExpiresAt:            xoutil.SqTime{token.Expiry},
		}
		err = dbToken.Save(tr.db)
		if err != nil {
			return token, err
		}

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
	token, err = tr.FetchNewToken(params)
	if err != nil {
		return token, err
	}
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

func (tr *TokenRequester) RetrieveNewToken(params providers.TokenRequestParams) (*oauth2.Token, error) {
	// retrieve new token
	tokenSource := tr.provider.TokenSource(oauth2.NoContext, params)
	return tokenSource.Token()
}

func (tr *TokenRequester) FetchNewToken(params providers.TokenRequestParams) (*oauth2.Token, error) {
	tokenChan, errChan := tr.AddRequest(params)

	// block on both channels
	token := <-tokenChan
	// @TODO: should the close be done here?
	close(tokenChan)
	err := <-errChan
	// @TODO: should the close be done here?
	close(errChan)

	return token, err
}
