package oauthproxy

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"

	"github.com/lytics/logrus"
	"github.com/omniboost/oauth-proxy/db"
	"github.com/omniboost/oauth-proxy/providers"
	"github.com/pkg/errors"
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
	// saving the token to a tokens map[string]*oauth2.Token based on the
	// parameters for the db query could make it faster?
	for {
		select {
		case request := <-tr.requests:
			if request.params.Code != "" {
				token, err := tr.CodeExchange(request)
				tr.handleResults(request, token, err)
			} else {
				token, err := tr.TokenRefresh(request)
				tr.handleResults(request, token, err)
			}
		case <-tr.ctx.Done():
			fmt.Println("done")
			return
			// default:
			// 	fmt.Println("default")
			// 	return
		}
	}
}

func (tr *TokenRequester) CodeExchange(req TokenRequest) (*Token, error) {
	// exchange code for token and save new token in db
	params := req.params
	logrus.Debugf("new code exchange request received (%s)", params.Code)

	opts := []oauth2.AuthCodeOption{}
	if params.CodeVerifier != "" {
		opts = append(opts, oauth2.SetAuthURLParam("code_verifier", params.CodeVerifier))
	}

	// custom http client
	client := &http.Client{}
	rt := NewRoundTripperWithSave(http.DefaultTransport)
	client.Transport = rt
	ctx := context.WithValue(context.TODO(), oauth2.HTTPClient, client)
	t, err := tr.provider.Exchange(ctx, params, opts...)
	token := &Token{Token: t, Raw: map[string]json.RawMessage{}}
	if err != nil {
		logrus.Errorf("something went wrong exchanging code (%s)", params.Code)
		return token, errors.WithStack(err)
	}

	logrus.Debugf("saving new token to database (%s)", token.RefreshToken)

	// params.RefreshToken is used for looking up the entry in the db. Make sure
	// it's not empty after a first time code exchange
	params.RefreshToken = token.RefreshToken

	b, err := ioutil.ReadAll(rt.LastResponseBody())
	if err != nil {
		return token, errors.WithStack(err)
	}

	// Add raw response body to token
	err = json.Unmarshal(b, &token.Raw)
	if err != nil {
		return token, errors.WithStack(err)
	}

	_, err = tr.SaveToken(token, params)
	if err != nil {
		logrus.Errorf("something went wrong saving a new token to the database (%s)", token.RefreshToken)
		return token, errors.WithStack(err)
	}
	return token, errors.WithStack(err)
}

func (tr *TokenRequester) TokenRefresh(req TokenRequest) (*Token, error) {
	params := req.params
	logrus.Debugf("new token refresh request received (%s)", params.RefreshToken)

	token := &Token{}
	dbToken, err := tr.DBTokenFromDB(params)
	if errors.Cause(err) == sql.ErrNoRows {
		// no results in db: request new token
		logrus.Debugf("couldn't find refresh token in database, requesting new token (%s)", params.RefreshToken)
		token, err := tr.fetchAndSaveNewToken(params)
		if err != nil {
			return token, errors.WithStack(err)
		}

		logrus.Debugf("sending new token to requester (%s)", params.RefreshToken)
		return token, errors.WithStack(err)
	} else if err != nil {
		logrus.Errorf("error retrieving token from database (%s): %s", params.RefreshToken, err)
		return token, errors.WithStack(err)
	} else {
		logrus.Debugf("found existing token in database (%s)", params.RefreshToken)
	}

	// existing token, check if still valid
	token, err = tr.DBTokenToOauth2Token(dbToken)
	if err != nil {
		return token, errors.WithStack(err)
	}

	if token.Valid() {
		// token is valid, use that
		logrus.Debugf("token valid until: %s", token.Expiry.String())
		logrus.Debugf("sending new token to requester (%s)", params.RefreshToken)
		return token, errors.WithStack(err)
	}

	logrus.Debugf("token (%s) isn't valid anymore, fetching new token", params.RefreshToken)
	logrus.Debugf("using latest refresh token (%s) to request new token", params.RefreshToken)

	params.RefreshToken = token.RefreshToken
	// if now code_verifier is sent, use the one used last time
	if params.CodeVerifier == "" && dbToken.CodeVerifier != "" {
		params.CodeVerifier = dbToken.CodeVerifier
	}
	token, err = tr.fetchAndSaveNewToken(params)
	if err != nil {
		return token, errors.WithStack(err)
	}

	// existing token, not valid
	logrus.Debugf("sending new token to requester (%s)", params.RefreshToken)
	return token, errors.WithStack(err)
}

func (tr *TokenRequester) Stop() {
	// ??
}

func (tr *TokenRequester) Request(params providers.TokenRequestParams) (*Token, error) {
	request := tr.NewTokenRequest(params)
	tr.requests <- request

	// block on both channels
	result := <-request.result
	close(request.result)
	return result.token, errors.WithStack(result.err)
}

func (tr *TokenRequester) NewTokenRequest(params providers.TokenRequestParams) TokenRequest {
	return TokenRequest{
		params: params,
		result: make(chan TokenRequestResult, 1),
	}
}

func (tr *TokenRequester) FetchNewToken(params providers.TokenRequestParams) (*oauth2.Token, error) {
	// retrieve new token
	logrus.Debugf("requesting new token with the following params :%+v", params)
	tokenSource := tr.provider.TokenSource(context.Background(), params)
	return tokenSource.Token()
}

func (tr *TokenRequester) DBTokenFromDB(params providers.TokenRequestParams) (*db.OauthToken, error) {
	// first check if there's an entry with the current refresh token
	dbToken, err := db.OauthTokenByAppClientIDClientSecretRefreshToken(context.Background(), tr.db, tr.provider.Name(), params.ClientID, params.ClientSecret, params.RefreshToken)
	if errors.Cause(err) == sql.ErrNoRows {
		// no result, check if there's an entry based on the original refresh
		// token
		dbToken, err = db.OauthTokenByAppClientIDClientSecretOriginalRefreshToken(context.Background(), tr.db, tr.provider.Name(), params.ClientID, params.ClientSecret, params.RefreshToken)
	}
	return dbToken, errors.WithStack(err)
}

func (tr *TokenRequester) TokenFromDB(params providers.TokenRequestParams) (*Token, error) {
	dbToken, err := tr.DBTokenFromDB(params)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	return tr.DBTokenToOauth2Token(dbToken)
}

func (tr *TokenRequester) DBTokenToOauth2Token(dbToken *db.OauthToken) (*Token, error) {
	var err error
	token := &Token{
		Token: &oauth2.Token{
			TokenType:    dbToken.Type,
			AccessToken:  dbToken.AccessToken,
			RefreshToken: dbToken.RefreshToken,
			Expiry:       dbToken.ExpiresAt.Time(),
		},
		Raw: map[string]json.RawMessage{},
	}

	if dbToken.CodeExchangeResponseBody.String == "" {
		token.Raw = map[string]json.RawMessage{}
	} else {
		err = json.Unmarshal([]byte(dbToken.CodeExchangeResponseBody.String), &token.Raw)
	}
	return token, errors.WithStack(err)
}

func (tr *TokenRequester) SaveNewTokenRequest(params providers.TokenRequestParams) (*db.TokenRequest, error) {
	tokenRequest := &db.TokenRequest{
		ID:                  0,
		App:                 tr.provider.Name(),
		RequestClientID:     params.ClientID,
		RequestClientSecret: params.ClientSecret,
		RequestRefreshToken: params.RefreshToken,
		RequestCode:         params.Code,
		RequestRedirectURL:  params.RedirectURL,
		RequestCodeVerifier: params.CodeVerifier,
		ResponseAccessToken: "",
		ResponseTokenType:   "",
		ResponseExpiry:      db.NewTime(time.Time{}),
		ResponseExtra:       "",
		CreatedAt:           db.NewTime(time.Now()),
		UpdatedAt:           db.NewTime(time.Now()),
	}

	err := tokenRequest.Save(context.Background(), tr.db)
	return tokenRequest, errors.WithStack(err)
}

func (tr *TokenRequester) AddTokenToTokenRequest(request *db.TokenRequest, token Token) (*db.TokenRequest, error) {
	extra, err := json.Marshal(token.Raw)
	if err != nil {
		return request, errors.WithStack(err)
	}
	request.ResponseAccessToken = token.AccessToken
	request.ResponseTokenType = token.TokenType
	request.ResponseRefreshToken = token.RefreshToken
	request.ResponseExpiry = db.NewTime(token.Expiry)
	request.ResponseExtra = string(extra)
	request.UpdatedAt = db.NewTime(time.Now())
	return request, request.Save(context.Background(), tr.db)
}

func (tr *TokenRequester) SaveToken(token *Token, params providers.TokenRequestParams) (db.OauthToken, error) {
	// @TODO: How to handle this better?
	// - remove the checking of ErrNoRows

	// grant_type=refresh_token
	originalRefreshToken := params.RefreshToken
	if params.RefreshToken == "" && token.RefreshToken != "" {
		// grant_type=code
		originalRefreshToken = params.RefreshToken
	}

	b, err := json.Marshal(token.Raw)
	if err != nil {
		return db.OauthToken{}, errors.WithStack(err)
	}

	dbToken, err := tr.DBTokenFromDB(params)
	if err != nil {
		if errors.Cause(err) == sql.ErrNoRows {
			dbToken = &db.OauthToken{
				App:                      tr.provider.Name(),
				Type:                     token.Type(),
				ClientID:                 params.ClientID,
				ClientSecret:             params.ClientSecret,
				OriginalRefreshToken:     originalRefreshToken,
				CreatedAt:                db.NewTime(time.Now()),
				CodeExchangeResponseBody: sql.NullString{string(b), true},
				CodeVerifier:             params.CodeVerifier,
			}
		} else {
			return db.OauthToken{}, errors.WithStack(err)
		}
	}

	if dbToken.ID != 0 {
		logrus.Debugf("found and existing token with id %d", dbToken.ID)
	}

	// Cockpit workaround
	e := token.Extra("expires")
	secs, ok := e.(float64)
	if token.Expiry.IsZero() && ok {
		token.Expiry = time.Now().Add(time.Duration(secs) * time.Second)
	}

	// update only changes
	dbToken.RefreshToken = token.RefreshToken
	dbToken.AccessToken = token.AccessToken
	expiry := db.NewTime(token.Expiry)
	dbToken.ExpiresAt = &expiry
	dbToken.UpdatedAt = db.NewTime(time.Now())
	return *dbToken, dbToken.Save(context.Background(), tr.db)
}

func (tr *TokenRequester) handleResults(request TokenRequest, token *Token, err error) {
	result := TokenRequestResult{
		token: token,
		err:   err,
	}
	request.result <- result
}

func (tr *TokenRequester) fetchAndSaveNewToken(params providers.TokenRequestParams) (*Token, error) {
	trDB, err := tr.SaveNewTokenRequest(params)
	if err != nil {
		return &Token{}, errors.WithStack(err)
	}

	t, err := tr.FetchNewToken(params)
	token := &Token{Token: t, Raw: map[string]json.RawMessage{}}
	if err != nil {
		logrus.Errorf("something went wrong fetching new token (%s): %s", params.RefreshToken, err)
		return token, errors.WithStack(err)
	}

	trDB, err = tr.AddTokenToTokenRequest(trDB, *token)
	if err != nil {
		return token, errors.WithStack(err)
	}

	logrus.Debugf("saving new token to database (%s)", params.RefreshToken)
	_, err = tr.SaveToken(token, params)
	if err != nil {
		logrus.Errorf("something went wrong saving a new token to the database (%s): %s", params.RefreshToken, err)
		return token, errors.WithStack(err)
	}

	return token, nil
}

type TokenRequest struct {
	params providers.TokenRequestParams
	result chan TokenRequestResult
}

type TokenRequestResult struct {
	token *Token
	err   error
}
