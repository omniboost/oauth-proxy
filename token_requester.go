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
	"github.com/omniboost/oauth-proxy/types"
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
	// for this to work the provider has to support the 'Authorization Code'
	// grant
	provider, ok := tr.provider.(providers.AuthorizationCodeProvider)
	if !ok {
		return nil, errors.Errorf("Provider '%s' doesn't support authorization code grant", tr.provider.Name())
	}

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
	t, err := provider.Exchange(ctx, params, opts...)
	token := &Token{Token: t, Raw: map[string]json.RawMessage{}}
	if err != nil {
		e := errors.Wrapf(err, "something went wrong exchanging code (%s)", params.Code)
		return token, e
	}

	// check id token if present
	idToken, ok := t.Extra("id_token").(string)
	if ok {
		if v, ok := provider.(interface {
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

	_, err = tr.SaveAuthorizationToken(tr.db, token, params)
	if err != nil {
		return token, err
	}

	return token, errors.WithStack(err)
}

func (tr *TokenRequester) IncrementNrOfSubsequentProviderErrors(db mysql.DB, token *mysql.OauthToken) error {
	token.NrOfSubsequentProviderErrors++
	token.UpdatedAt = time.Now()
	return token.Save(context.Background(), db)
}

func (tr *TokenRequester) TokenRefreshAuthorizationCode(req TokenRequest) (*Token, error) {
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
			logrus.Debug(err.Error())
			trx.Rollback()
		} else {
			err = trx.Commit()
		}
	}()

	dbToken, err := tr.AuthorizationTokenFromDB(trx, params)
	if errors.Cause(err) == sql.ErrNoRows {
		// no results in db: request new token
		logrus.Debugf("couldn't find refresh token in database, requesting new token (%s)", params.RefreshToken)
		token, err = tr.fetchAndSaveNewAuthorizationToken(trx, params)
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
		logrus.Debugf("sending existing token to requester (%s)", params.RefreshToken)
		return token, errors.WithStack(err)
	}

	logrus.Debugf("token (%s) isn't valid anymore, fetching new token", params.RefreshToken)
	logrus.Debugf("using latest refresh token (%s) to request new token", params.RefreshToken)

	params.RefreshToken = token.RefreshToken
	// if now code_verifier is sent, use the one used last time
	if params.CodeVerifier == "" && dbToken.CodeVerifier != "" {
		params.CodeVerifier = dbToken.CodeVerifier
	}
	token, err = tr.fetchAndSaveNewAuthorizationToken(trx, params)
	if err != nil {
		// check if we could find the token from the request in the db
		if dbToken.ID != 0 {
			// we found a token, increment the error counter
			// rollback the transaction first so we can use a non-transactional
			// db connection
			trx.Rollback()
			tr.IncrementNrOfSubsequentProviderErrors(tr.db, dbToken)
		}

		return token, errors.WithStack(err)
	}

	// existing token, not valid
	logrus.Debugf("sending new token to requester (%s)", params.RefreshToken)
	return token, errors.WithStack(err)
}

func (tr *TokenRequester) TokenRefresh(req TokenRequest) (*Token, error) {
	if req.params.GrantType == "password" {
		return tr.TokenRefreshPassword(req)
	}

	if req.params.GrantType == "client_credentials" {
		return tr.TokenRefreshClientCredentials(req)
	}

	return tr.TokenRefreshAuthorizationCode(req)
}

func (tr *TokenRequester) TokenRefreshPassword(req TokenRequest) (*Token, error) {
	var err error
	token := &Token{}
	params := req.params
	if params.Password == "" {
		return nil, errors.New("password is empty")
	}

	logrus.Debugf("new password token refresh request received (%s)", params.Username)

	trx, err := tr.db.Begin()
	if err != nil {
		return token, errors.WithStack(err)
	}
	defer func() {
		if err != nil {
			logrus.Debug(err.Error())
			trx.Rollback()
		} else {
			err = trx.Commit()
		}
	}()

	dbToken, err := tr.PasswordTokenFromDB(trx, params)
	if errors.Cause(err) == sql.ErrNoRows {
		// no results in db: request new token
		logrus.Debugf("couldn't find refresh token in database, requesting new token (%s)", params.Username)
		token, err = tr.fetchAndSaveNewPasswordToken(trx, params)
		if err != nil {
			return token, errors.WithStack(err)
		}

		logrus.Debugf("sending new token to requester (%s)", params.RefreshToken)
		return token, errors.WithStack(err)
	} else if err != nil {
		e := errors.Wrapf(err, "error retrieving token from database (%s): %s", params.Username, err)
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
		logrus.Debugf("sending existing token to requester (%s)", params.Username)
		return token, errors.WithStack(err)
	}

	logrus.Debugf("token (%s) isn't valid anymore, fetching new token", params.Username)
	logrus.Debugf("using latest refresh token (%s) to request new token", params.Username)

	params.RefreshToken = token.RefreshToken
	// if now code_verifier is sent, use the one used last time
	if params.CodeVerifier == "" && dbToken.CodeVerifier != "" {
		params.CodeVerifier = dbToken.CodeVerifier
	}
	token, err = tr.fetchAndSaveNewPasswordToken(trx, params)
	if err != nil {
		// check if we could find the token from the request in the db
		if dbToken.ID != 0 {
			// we found a token, increment the error counter
			// rollback the transaction first so we can use a non-transactional
			// db connection
			trx.Rollback()
			tr.IncrementNrOfSubsequentProviderErrors(tr.db, dbToken)
		}

		return token, errors.WithStack(err)
	}

	// existing token, not valid
	logrus.Debugf("sending new token to requester (%s)", params.Username)
	return token, errors.WithStack(err)
}

func (tr *TokenRequester) TokenRefreshClientCredentials(req TokenRequest) (*Token, error) {
	var err error
	token := &Token{}
	params := req.params

	logrus.Debugf("new client_credentials token refresh request received (%s:%s)", params.ClientID, params.ClientSecret)

	trx, err := tr.db.Begin()
	if err != nil {
		return token, errors.WithStack(err)
	}
	defer func() {
		if err != nil {
			logrus.Debug(err.Error())
			trx.Rollback()
		} else {
			err = trx.Commit()
		}
	}()

	dbToken, err := tr.ClientCredentialsTokenFromDB(trx, params)
	if errors.Cause(err) == sql.ErrNoRows {
		// no results in db: request new token
		logrus.Debugf("couldn't find access token in database, requesting new token")
		token, err = tr.fetchAndSaveNewClientCredentialsToken(trx, params)
		if err != nil {
			return token, errors.WithStack(err)
		}

		logrus.Debugf("sending new token to requester (%s)", token.AccessToken)
		return token, errors.WithStack(err)
	} else if err != nil {
		e := errors.Wrapf(err, "error retrieving token from database: %s", err)
		return token, e
	} else {
		logrus.Debugf("found existing token in database (%s)", dbToken.AccessToken)
	}

	// existing token, check if still valid
	token, err = tr.DBTokenToOauth2Token(dbToken)
	if err != nil {
		return token, errors.WithStack(err)
	}

	if token.Valid() {
		// token is valid, use that
		logrus.Debugf("token valid until: %s", token.Expiry.String())
		logrus.Debugf("sending existing token to requester (%s)", token.AccessToken)
		return token, errors.WithStack(err)
	}

	logrus.Debugf("token (%s) isn't valid anymore, fetching new token", token.AccessToken)

	params.RefreshToken = token.RefreshToken
	// if now code_verifier is sent, use the one used last time
	if params.CodeVerifier == "" && dbToken.CodeVerifier != "" {
		params.CodeVerifier = dbToken.CodeVerifier
	}
	token, err = tr.fetchAndSaveNewClientCredentialsToken(trx, params)
	if err != nil {
		// check if we could find the token from the request in the db
		if dbToken.ID != 0 {
			// we found a token, increment the error counter
			// rollback the transaction first so we can use a non-transactional
			// db connection
			trx.Rollback()
			tr.IncrementNrOfSubsequentProviderErrors(tr.db, dbToken)
		}

		return token, errors.WithStack(err)
	}

	// existing token, not valid
	logrus.Debugf("sending new token to requester (%s)", params.Username)
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

func (tr *TokenRequester) FetchNewTokenAuthorizationCode(params providers.TokenRequestParams) (*oauth2.Token, error) {
	prov, ok := tr.provider.(providers.AuthorizationCodeProvider)
	if !ok {
		return nil, errors.Errorf("Provider '%s' doesn't support authorization code grant", tr.provider.Name())
	}

	// retrieve new token
	logrus.Debugf("requesting new token with the following params :%+v", params)
	token, err := prov.TokenSourceAuthorizationCode(context.Background(), params).Token()
	if err != nil {
		return token, errors.WithStack(err)
	}

	// verify id_token
	err = tr.VerifyIDToken(token, params)
	if err != nil {
		return token, errors.WithStack(err)
	}

	return token, nil
}

func (tr *TokenRequester) FetchNewTokenPassword(params providers.TokenRequestParams) (*oauth2.Token, error) {
	prov, ok := tr.provider.(providers.PasswordProvider)
	if !ok {
		return nil, errors.Errorf("Provider '%s' doesn't support password grant", tr.provider.Name())
	}

	// retrieve new token
	logrus.Debugf("requesting new token with the following params :%+v", params)
	token, err := prov.TokenSourcePassword(context.Background(), params).Token()
	if err != nil {
		return token, errors.WithStack(err)
	}

	// verify id_token
	err = tr.VerifyIDToken(token, params)
	if err != nil {
		return token, errors.WithStack(err)
	}

	return token, nil
}

func (tr *TokenRequester) FetchNewTokenClientCredentials(params providers.TokenRequestParams) (*oauth2.Token, error) {
	prov, ok := tr.provider.(providers.ClientCredentialsProvider)
	if !ok {
		return nil, errors.Errorf("Provider '%s' doesn't support client credentials grant", tr.provider.Name())
	}

	// retrieve new token
	logrus.Debugf("requesting new token with the following params :%+v", params)
	token, err := prov.TokenSourceClientCredentials(context.Background(), params).Token()
	if err != nil {
		return token, errors.WithStack(err)
	}

	// verify id_token
	err = tr.VerifyIDToken(token, params)
	if err != nil {
		return token, errors.WithStack(err)
	}

	return token, nil
}

func (tr *TokenRequester) VerifyIDToken(token *oauth2.Token, params providers.TokenRequestParams) error {
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
					return errors.WithStack(err)
				}
			}
		}
	}

	return nil
}

func (tr *TokenRequester) AuthorizationTokenFromDB(db mysql.DB, params providers.TokenRequestParams) (*mysql.OauthToken, error) {
	// first check if there's an entry with the current refresh token
	dbToken, err := mysql.OauthTokenByAppClientIDClientSecretRefreshTokenOrOriginalRefreshToken(context.Background(), db, tr.provider.Name(), params.ClientID, params.ClientSecret, params.RefreshToken)
	return dbToken, errors.WithStack(err)
}

func (tr *TokenRequester) PasswordTokenFromDB(db mysql.DB, params providers.TokenRequestParams) (*mysql.OauthToken, error) {
	// first check if there's an entry with the current refresh token
	dbToken, err := mysql.OauthTokenByAppClientIDClientSecretUsername(context.Background(), db, tr.provider.Name(), params.ClientID, params.ClientSecret, params.Username)
	return dbToken, errors.WithStack(err)
}

func (tr *TokenRequester) ClientCredentialsTokenFromDB(db mysql.DB, params providers.TokenRequestParams) (*mysql.OauthToken, error) {
	// first check if there's an entry with the current refresh token
	dbToken, err := mysql.OauthTokenByAppClientIDClientSecret(context.Background(), db, tr.provider.Name(), params.ClientID, params.ClientSecret)
	return dbToken, errors.WithStack(err)
}

func (tr *TokenRequester) DBTokenToOauth2Token(dbToken *mysql.OauthToken) (*Token, error) {
	var err error

	token := &Token{
		Token: &oauth2.Token{
			TokenType:    dbToken.Type,
			AccessToken:  string(dbToken.AccessToken),
			RefreshToken: string(dbToken.RefreshToken),
			Expiry:       dbToken.ExpiresAt.Time,
		},
		Raw: map[string]json.RawMessage{},
	}

	if dbToken.CodeExchangeResponseBody == "" {
		token.Raw = map[string]json.RawMessage{}
	} else {
		err = json.Unmarshal([]byte(dbToken.CodeExchangeResponseBody), &token.Raw)
	}
	return token, errors.WithStack(err)
}

func (tr *TokenRequester) SaveNewTokenRequest(db mysql.DB, params providers.TokenRequestParams) (*mysql.TokenRequest, error) {
	tokenRequest := &mysql.TokenRequest{
		ID:                  0,
		App:                 tr.provider.Name(),
		RequestGrantType:    params.GrantType,
		RequestClientID:     params.ClientID,
		RequestClientSecret: params.ClientSecret,
		RequestUsername:     params.Username,
		RequestRefreshToken: params.RefreshToken,
		RequestCode:         params.Code,
		RequestRedirectURL:  params.RedirectURL,
		RequestCodeVerifier: params.CodeVerifier,
		ResponseAccessToken: "",
		ResponseTokenType:   "",
		ResponseExpiry:      sql.NullTime{},
		ResponseExtra:       "",
		CreatedAt:           time.Now(),
		UpdatedAt:           time.Now(),
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
	request.UpdatedAt = time.Now()
	return request, request.Save(context.Background(), db)
}

func (tr *TokenRequester) SaveAuthorizationToken(db mysql.DB, token *Token, params providers.TokenRequestParams) (mysql.OauthToken, error) {
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

	dbToken, err := tr.AuthorizationTokenFromDB(db, params)
	if err != nil {
		if errors.Cause(err) == sql.ErrNoRows {
			dbToken = &mysql.OauthToken{
				App:                          tr.provider.Name(),
				Type:                         token.Type(),
				GrantType:                    params.GrantType,
				ClientID:                     params.ClientID,
				ClientSecret:                 types.OptionallyEncryptedString(params.ClientSecret),
				ClientSecretHash:             mysql.NewClientSecretHash(params.ClientID, params.ClientSecret),
				Username:                     params.Username,
				OriginalRefreshToken:         types.OptionallyEncryptedString(originalRefreshToken),
				OriginalRefreshTokenHash:     mysql.NewOriginalRefreshTokenHash(params.ClientID, originalRefreshToken),
				CreatedAt:                    time.Now(),
				CodeExchangeResponseBody:     types.OptionallyEncryptedString(b),
				CodeVerifier:                 params.CodeVerifier,
				NrOfSubsequentProviderErrors: 0,
			}
		} else {
			return mysql.OauthToken{}, errors.WithStack(err)
		}
	}

	if dbToken.ID != 0 {
		logrus.Debugf("found and existing token with id %d", dbToken.ID)
	} else {
		logrus.Debugf("New token")
	}

	// Cockpit workaround
	e := token.Extra("expires")
	secs, ok := e.(float64)
	if token.Expiry.IsZero() && ok {
		token.Expiry = time.Now().Add(time.Duration(secs) * time.Second)
	}

	// update only changes
	dbToken.RefreshToken = types.OptionallyEncryptedString(token.RefreshToken)
	dbToken.RefreshTokenHash = mysql.NewRefreshTokenHash(dbToken.ClientID, token.RefreshToken)
	dbToken.AccessToken = types.OptionallyEncryptedString(token.AccessToken)
	dbToken.AccessTokenHash = mysql.NewAccessTokenHash(dbToken.ClientID, token.AccessToken)
	dbToken.ExpiresAt = sql.NullTime{Time: token.Expiry, Valid: true}
	dbToken.UpdatedAt = time.Now()
	return *dbToken, dbToken.Save(context.Background(), db)
}

func (tr *TokenRequester) SavePasswordToken(db mysql.DB, token *Token, params providers.TokenRequestParams) (mysql.OauthToken, error) {
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

	dbToken, err := tr.PasswordTokenFromDB(db, params)
	if err != nil {
		if errors.Cause(err) == sql.ErrNoRows {
			dbToken = &mysql.OauthToken{
				App:                      tr.provider.Name(),
				Type:                     token.Type(),
				GrantType:                params.GrantType,
				ClientID:                 params.ClientID,
				ClientSecret:             types.OptionallyEncryptedString(params.ClientSecret),
				ClientSecretHash:         mysql.NewClientSecretHash(params.ClientID, params.ClientSecret),
				Username:                 params.Username,
				OriginalRefreshToken:     types.OptionallyEncryptedString(originalRefreshToken),
				OriginalRefreshTokenHash: mysql.NewOriginalRefreshTokenHash(params.ClientID, originalRefreshToken),
				CreatedAt:                time.Now(),
				CodeExchangeResponseBody: types.OptionallyEncryptedString(b),
				CodeVerifier:             params.CodeVerifier,
			}
		} else {
			return mysql.OauthToken{}, errors.WithStack(err)
		}
	}

	if dbToken.ID != 0 {
		logrus.Debugf("found and existing token with id %d", dbToken.ID)
	} else {
		logrus.Debugf("New token")
	}

	// Cockpit workaround
	e := token.Extra("expires")
	secs, ok := e.(float64)
	if token.Expiry.IsZero() && ok {
		token.Expiry = time.Now().Add(time.Duration(secs) * time.Second)
	}

	// update only changes
	dbToken.RefreshToken = types.OptionallyEncryptedString(token.RefreshToken)
	dbToken.RefreshTokenHash = mysql.NewRefreshTokenHash(dbToken.ClientID, token.RefreshToken)
	dbToken.AccessToken = types.OptionallyEncryptedString(token.AccessToken)
	dbToken.AccessTokenHash = mysql.NewAccessTokenHash(dbToken.ClientID, token.AccessToken)
	dbToken.ExpiresAt = sql.NullTime{Time: token.Expiry, Valid: true}
	dbToken.UpdatedAt = time.Now()
	return *dbToken, dbToken.Save(context.Background(), db)
}

func (tr *TokenRequester) SaveClientCredentialsToken(db mysql.DB, token *Token, params providers.TokenRequestParams) (mysql.OauthToken, error) {
	// @TODO: How to handle this better?
	// - remove the checking of ErrNoRows

	// grant_type=client_credentials
	b, err := json.Marshal(token.Raw)
	if err != nil {
		return mysql.OauthToken{}, errors.WithStack(err)
	}

	dbToken, err := tr.ClientCredentialsTokenFromDB(db, params)
	if err != nil {
		if errors.Cause(err) == sql.ErrNoRows {
			dbToken = &mysql.OauthToken{
				App:                      tr.provider.Name(),
				Type:                     token.Type(),
				GrantType:                params.GrantType,
				ClientID:                 params.ClientID,
				ClientSecret:             types.OptionallyEncryptedString(params.ClientSecret),
				ClientSecretHash:         mysql.NewClientSecretHash(params.ClientID, params.ClientSecret),
				Username:                 params.Username,
				OriginalRefreshToken:     "",
				OriginalRefreshTokenHash: mysql.NewOriginalRefreshTokenHash(params.ClientID, ""),
				CreatedAt:                time.Now(),
				CodeExchangeResponseBody: types.OptionallyEncryptedString(b),
				CodeVerifier:             params.CodeVerifier,
			}
		} else {
			return mysql.OauthToken{}, errors.WithStack(err)
		}
	}

	if dbToken.ID != 0 {
		logrus.Debugf("found and existing token with id %d", dbToken.ID)
	} else {
		logrus.Debugf("New token")
	}

	// Cockpit workaround
	e := token.Extra("expires")
	secs, ok := e.(float64)
	if token.Expiry.IsZero() && ok {
		token.Expiry = time.Now().Add(time.Duration(secs) * time.Second)
	}

	// update only changes
	dbToken.RefreshToken = types.OptionallyEncryptedString(token.RefreshToken)
	dbToken.RefreshTokenHash = mysql.NewRefreshTokenHash(dbToken.ClientID, token.RefreshToken)
	dbToken.AccessToken = types.OptionallyEncryptedString(token.AccessToken)
	dbToken.AccessTokenHash = mysql.NewAccessTokenHash(dbToken.ClientID, token.AccessToken)
	dbToken.ExpiresAt = sql.NullTime{Time: token.Expiry, Valid: true}
	dbToken.UpdatedAt = time.Now()
	return *dbToken, dbToken.Save(context.Background(), db)
}

func (tr *TokenRequester) handleResults(request TokenRequest, token *Token, err error) {
	result := TokenRequestResult{
		token: token,
		err:   err,
	}
	request.result <- result
}

func (tr *TokenRequester) fetchAndSaveNewAuthorizationToken(db mysql.DB, params providers.TokenRequestParams) (*Token, error) {
	trDB, err := tr.SaveNewTokenRequest(db, params)
	if err != nil {
		return &Token{}, errors.WithStack(err)
	}

	t, err := tr.FetchNewTokenAuthorizationCode(params)
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
	_, err = tr.SaveAuthorizationToken(db, token, params)
	if err != nil {
		e := errors.Wrapf(err, "something went wrong saving a new token to the database (%s): %s", params.RefreshToken, err)
		return token, e
	}

	return token, nil
}

func (tr *TokenRequester) fetchAndSaveNewPasswordToken(db mysql.DB, params providers.TokenRequestParams) (*Token, error) {
	trDB, err := tr.SaveNewTokenRequest(db, params)
	if err != nil {
		return &Token{}, errors.WithStack(err)
	}

	t, err := tr.FetchNewTokenPassword(params)
	token := &Token{Token: t, Raw: map[string]json.RawMessage{}}
	if err != nil {
		e := errors.Wrapf(err, "something went wrong fetching new token (%s): %s", params.Username, err)
		return token, e
	}

	trDB, err = tr.AddTokenToTokenRequest(db, trDB, *token)
	if err != nil {
		return token, errors.WithStack(err)
	}

	logrus.Debugf("saving new token to database (%s)", params.Username)
	_, err = tr.SavePasswordToken(db, token, params)
	if err != nil {
		e := errors.Wrapf(err, "something went wrong saving a new token to the database (%s): %s", params.Username, err)
		return token, e
	}

	return token, nil
}

func (tr *TokenRequester) fetchAndSaveNewClientCredentialsToken(db mysql.DB, params providers.TokenRequestParams) (*Token, error) {
	trDB, err := tr.SaveNewTokenRequest(db, params)
	if err != nil {
		return &Token{}, errors.WithStack(err)
	}

	t, err := tr.FetchNewTokenClientCredentials(params)
	token := &Token{Token: t, Raw: map[string]json.RawMessage{}}
	if err != nil {
		e := errors.Wrapf(err, "something went wrong fetching new token: %s", err)
		return token, e
	}

	trDB, err = tr.AddTokenToTokenRequest(db, trDB, *token)
	if err != nil {
		return token, errors.WithStack(err)
	}

	logrus.Debugf("saving new token to database (%s)", token.AccessToken)
	_, err = tr.SaveClientCredentialsToken(db, token, params)
	if err != nil {
		e := errors.Wrapf(err, "something went wrong saving a new token to the database (%s): %s", token.AccessToken, err)
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
