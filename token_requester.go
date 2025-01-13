package oauthproxy

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/lytics/logrus"
	"github.com/omniboost/oauth-proxy/mysql"
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
		e := errors.Wrapf(err, "something went wrong exchanging code (%s)", params.Code)
		return token, e
	}

	// check id token if present
	idToken, ok := t.Extra("id_token").(string)
	if ok {
		if v, ok := tr.provider.(interface {
			IDTokenVerifier(providers.TokenRequestParams) *oidc.IDTokenVerifier
		}); ok {
			_, err := v.IDTokenVerifier(params).Verify(context.Background(), idToken)
			if err != nil {
				if strings.Contains(err.Error(), "failed to decode keys") {
					// do nothing
				} else {
					return token, errors.WithStack(err)
				}
			}
		}
	}

	logrus.Debugf("saving new token to database (%s)", token.RefreshToken)

	// params.RefreshToken is used for looking up the entry in the mysql. Make sure
	// it's not empty after a first time code exchange
	params.RefreshToken = token.RefreshToken

	b, err := io.ReadAll(rt.LastResponseBody())
	if err != nil {
		return token, errors.WithStack(err)
	}

	// Add raw response body to token
	err = json.Unmarshal(b, &token.Raw)
	if err != nil {
		return token, errors.WithStack(err)
	}

	_, err = tr.SaveToken(tr.db, token, params)
	if err != nil {
		return token, err
	}

	return token, errors.WithStack(err)
}

func (tr *TokenRequester) TokenRefresh(req TokenRequest) (*Token, error) {
	var err error
	token := &Token{}
	params := req.params
	if params.RefreshToken == "" {
		return nil, errors.New("refresh token is empty")
	}

	logrus.Debugf("new token refresh request received (%s)", params.RefreshToken)

	trx, err := tr.db.Begin()
	if err != nil {
		return token, errors.WithStack(err)
	}
	defer func() {
		if err != nil {
			logrus.Debugf(err.Error())
			trx.Rollback()
		} else {
			err = trx.Commit()
		}
	}()

	// // lock db for this key
	// key := strings.Join([]string{tr.provider.Name(), params.ClientID, params.ClientSecret, params.RefreshToken}, ":")
	// _, err := tr.db.Exec("SELECT GET_LOCK(?, 10)", key)
	// if err != nil {
	// 	return token, errors.WithStack(err)
	// }
	// defer func() {
	// 	_, err := tr.db.Exec("SELECT RELEASE_LOCK(?)", key)
	// 	if err != nil {
	// 		logrus.Debugf(err.Error())
	// 	}
	// }()

	dbToken, err := tr.DBTokenFromDB(trx, params)
	if errors.Cause(err) == sql.ErrNoRows {
		// no results in db: request new token
		logrus.Debugf("couldn't find refresh token in database, requesting new token (%s)", params.RefreshToken)
		token, err = tr.fetchAndSaveNewToken(trx, params)
		if err != nil {
			return token, errors.WithStack(err)
		}

		logrus.Debugf("sending new token to requester (%s)", params.RefreshToken)
		return token, errors.WithStack(err)
	} else if err != nil {
		e := errors.Wrapf(err, "error retrieving token from database (%s): %s", params.RefreshToken, err)
		return token, e
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
	token, err = tr.fetchAndSaveNewToken(trx, params)
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
	token, err := tr.provider.TokenSource(context.Background(), params).Token()
	if err != nil {
		return token, errors.WithStack(err)
	}

	// check id token if present
	idToken, ok := token.Extra("id_token").(string)
	if ok {
		if v, ok := tr.provider.(interface {
			IDTokenVerifier(providers.TokenRequestParams) *oidc.IDTokenVerifier
		}); ok {
			_, err := v.IDTokenVerifier(params).Verify(context.Background(), idToken)
			if err != nil {
				if strings.Contains(err.Error(), "failed to decode keys") {
					// do nothing
				} else {
					return token, errors.WithStack(err)
				}
			}
		}
	}

	return token, nil
}

func (tr *TokenRequester) DBTokenFromDB(db mysql.DB, params providers.TokenRequestParams) (*mysql.OauthToken, error) {
	// first check if there's an entry with the current refresh token
	dbToken, err := mysql.OauthTokenByAppClientIDClientSecretRefreshTokenOrOriginalRefreshToken(context.Background(), db, tr.provider.Name(), params.ClientID, params.ClientSecret, params.RefreshToken)
	return dbToken, errors.WithStack(err)
}

func (tr *TokenRequester) TokenFromDB(db mysql.DB, params providers.TokenRequestParams) (*Token, error) {
	dbToken, err := tr.DBTokenFromDB(db, params)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	return tr.DBTokenToOauth2Token(dbToken)
}

func (tr *TokenRequester) DBTokenToOauth2Token(dbToken *mysql.OauthToken) (*Token, error) {
	var err error

	token := &Token{
		Token: &oauth2.Token{
			TokenType:    dbToken.Type,
			AccessToken:  dbToken.AccessToken,
			RefreshToken: dbToken.RefreshToken,
			Expiry:       dbToken.ExpiresAt.Time,
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

func (tr *TokenRequester) SaveNewTokenRequest(db mysql.DB, params providers.TokenRequestParams) (*mysql.TokenRequest, error) {
	tokenRequest := &mysql.TokenRequest{
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
		ResponseExpiry:      sql.NullTime{},
		ResponseExtra:       "",
		CreatedAt:           (time.Now()),
		UpdatedAt:           (time.Now()),
	}

	err := tokenRequest.Save(context.Background(), db)
	return tokenRequest, errors.WithStack(err)
}

func (tr *TokenRequester) AddTokenToTokenRequest(db mysql.DB, request *mysql.TokenRequest, token Token) (*mysql.TokenRequest, error) {
	extra, err := json.Marshal(token.Raw)
	if err != nil {
		return request, errors.WithStack(err)
	}
	request.ResponseAccessToken = token.AccessToken
	request.ResponseTokenType = token.TokenType
	request.ResponseRefreshToken = token.RefreshToken
	request.ResponseExpiry = sql.NullTime{Time: token.Expiry, Valid: true}
	request.ResponseExtra = string(extra)
	request.UpdatedAt = (time.Now())
	return request, request.Save(context.Background(), db)
}

func (tr *TokenRequester) SaveToken(db mysql.DB, token *Token, params providers.TokenRequestParams) (mysql.OauthToken, error) {
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
		return mysql.OauthToken{}, errors.WithStack(err)
	}

	dbToken, err := tr.DBTokenFromDB(db, params)
	if err != nil {
		if errors.Cause(err) == sql.ErrNoRows {
			dbToken = &mysql.OauthToken{
				App:                      tr.provider.Name(),
				Type:                     token.Type(),
				ClientID:                 params.ClientID,
				ClientSecret:             params.ClientSecret,
				OriginalRefreshToken:     originalRefreshToken,
				CreatedAt:                (time.Now()),
				CodeExchangeResponseBody: sql.NullString{String: string(b), Valid: true},
				CodeVerifier:             params.CodeVerifier,
			}
		} else {
			return mysql.OauthToken{}, errors.WithStack(err)
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
	dbToken.ExpiresAt = sql.NullTime{Time: token.Expiry, Valid: true}
	dbToken.UpdatedAt = (time.Now())
	return *dbToken, dbToken.Save(context.Background(), db)
}

func (tr *TokenRequester) handleResults(request TokenRequest, token *Token, err error) {
	result := TokenRequestResult{
		token: token,
		err:   err,
	}
	request.result <- result
}

func (tr *TokenRequester) fetchAndSaveNewToken(db mysql.DB, params providers.TokenRequestParams) (*Token, error) {
	trDB, err := tr.SaveNewTokenRequest(db, params)
	if err != nil {
		return &Token{}, errors.WithStack(err)
	}

	t, err := tr.FetchNewToken(params)
	token := &Token{Token: t, Raw: map[string]json.RawMessage{}}
	if err != nil {
		e := errors.Wrapf(err, "something went wrong fetching new token (%s): %s", params.RefreshToken, err)
		return token, e
	}

	trDB, err = tr.AddTokenToTokenRequest(db, trDB, *token)
	if err != nil {
		return token, errors.WithStack(err)
	}

	logrus.Debugf("saving new token to database (%s)", params.RefreshToken)
	_, err = tr.SaveToken(db, token, params)
	if err != nil {
		e := errors.Wrapf(err, "something went wrong saving a new token to the database (%s): %s", params.RefreshToken, err)
		return token, e
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
