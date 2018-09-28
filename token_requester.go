package oauthproxy

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"bitbucket.org/tim_online/oauth-proxy/db"
	"bitbucket.org/tim_online/oauth-proxy/providers"
	"github.com/lytics/logrus"
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
		db:       db,
		provider: provider,
		requests: make(chan TokenRequest, 2),
		ctx:      ctx,
		// tokenChans: []chan *oauth2.Token{},
		// errChans:   []chan error{},
	}
}

type TokenRequester struct {
	db       *sql.DB
	provider providers.Provider
	requests chan TokenRequest
	ctx      context.Context
}

func (tr *TokenRequester) Start() {
	go func() {
		tr.Listen()
	}()
}

func (tr *TokenRequester) Listen() {
	var token *oauth2.Token

	handleResults := func(request TokenRequest, token *oauth2.Token, err error) {
		result := TokenRequestResult{
			token: token,
			err:   err,
		}
		request.result <- result
	}

	for {
		select {
		case request := <-tr.requests:
			var err error
			params := request.params
			logrus.Debugf("new token request received (%s)", params.RefreshToken)

			if token == nil {
				token, err = tr.TokenFromDB(params)
				if err == sql.ErrNoRows {
					// no results in db: request new token
					token, err = tr.FetchNewToken(params)
					if err != nil {
						logrus.Errorf("something went wrong fetching new token (%s)", params.RefreshToken)
						handleResults(request, token, err)
						continue
					}

					err = tr.SaveToken(token, params)
					if err != nil {
						logrus.Errorf("something went wrong saving a new token to the database (%s)", params.RefreshToken)
						handleResults(request, token, err)
						continue
					}

					logrus.Debugf("sending new token to requester (%s)", params.RefreshToken)
					handleResults(request, token, nil)
				} else if err != nil {
					logrus.Errorf("error retrieving token from database (%s)", params.RefreshToken)
					handleResults(request, token, err)
					continue
				} else {
					logrus.Debugf("found existing token in database (%s)", params.RefreshToken)
				}
			}

			// existing token, check if still valid
			if token.Valid() {
				// token is valid, use that
				logrus.Debugf("sending new token to requester (%s)", params.RefreshToken)
				handleResults(request, token, nil)
				continue
			}

			logrus.Debugf("token (%s) isn't valid anymore, fetching new token", params.RefreshToken)
			token, err = tr.FetchNewToken(params)
			if err != nil {
				logrus.Errorf("something went wrong fetching new token (%s)", params.RefreshToken)
				handleResults(request, token, err)
				continue
			}

			err = tr.SaveToken(token, params)
			if err != nil {
				logrus.Errorf("something went wrong saving a new token to the database (%s)", params.RefreshToken)
				handleResults(request, token, err)
				continue
			}

			// existing token, not valid
			logrus.Debugf("sending new token to requester (%s)", params.RefreshToken)
			handleResults(request, token, nil)
		case <-tr.ctx.Done():
			fmt.Println("done")
			return
			// default:
			// 	fmt.Println("default")
			// 	return
		}
	}
}

func (tr *TokenRequester) Stop() {
	// ??
}

func (tr *TokenRequester) Request(params providers.TokenRequestParams) (*oauth2.Token, error) {
	request := tr.NewTokenRequest(params)
	tr.requests <- request

	// block on both channels
	result := <-request.result
	close(request.result)
	return result.token, result.err
}

func (tr *TokenRequester) NewTokenRequest(params providers.TokenRequestParams) TokenRequest {
	return TokenRequest{
		params: params,
		result: make(chan TokenRequestResult, 1),
	}
}

func (tr *TokenRequester) FetchNewToken(params providers.TokenRequestParams) (*oauth2.Token, error) {
	// retrieve new token
	tokenSource := tr.provider.TokenSource(oauth2.NoContext, params)
	return tokenSource.Token()
}

func (tr *TokenRequester) TokenFromDB(params providers.TokenRequestParams) (*oauth2.Token, error) {
	dbToken, err := db.OauthTokenByAppClientIDClientSecretOriginalRefreshToken(tr.db, tr.provider.Name(), params.ClientID, params.ClientSecret, params.RefreshToken)
	if err != nil {
		return nil, err
	}

	token := &oauth2.Token{
		TokenType:    dbToken.Type,
		AccessToken:  dbToken.AccessToken,
		RefreshToken: dbToken.RefreshToken,
		Expiry:       dbToken.ExpiresAt.Time,
	}
	return token, nil
}

func (tr *TokenRequester) SaveToken(token *oauth2.Token, params providers.TokenRequestParams) error {
	// @TODO: How to handle this better?
	// - remove the checking of ErrNoRows
	dbToken, err := db.OauthTokenByAppClientIDClientSecretOriginalRefreshToken(tr.db, tr.provider.Name(), params.ClientID, params.ClientSecret, params.RefreshToken)
	if err != nil {
		if err == sql.ErrNoRows {
			dbToken = &db.OauthToken{
				CreatedAt: xoutil.SqTime{time.Now()},
			}
		} else {
			return err
		}
	}

	dbToken.App = tr.provider.Name()
	dbToken.Type = token.Type()
	dbToken.ClientID = params.ClientID
	dbToken.ClientSecret = params.ClientSecret
	dbToken.OriginalRefreshToken = params.RefreshToken
	dbToken.RefreshToken = token.RefreshToken
	dbToken.AccessToken = token.AccessToken
	dbToken.ExpiresAt = xoutil.SqTime{token.Expiry}
	// dbToken.CreatedAt = dbToken.CreatedAt
	dbToken.UpdatedAt = xoutil.SqTime{time.Now()}
	return dbToken.Save(tr.db)
}

type TokenRequest struct {
	params providers.TokenRequestParams
	result chan TokenRequestResult
}

type TokenRequestResult struct {
	token *oauth2.Token
	err   error
}
