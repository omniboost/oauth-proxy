package oauthproxy

import (
	"context"
	"database/sql"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/getsentry/sentry-go"
	"github.com/omniboost/oauth-proxy/mysql"
	"github.com/omniboost/oauth-proxy/providers"
	"github.com/pkg/errors"
	"golang.org/x/oauth2"
)

// tokenRevokeTimeout limits a revoke request to the provider. Revoke requests
// are handled one at a time per provider, so a hanging provider would block
// all other revoke requests for that provider.
var tokenRevokeTimeout = 10 * time.Second

func NewTokenRevoker(db *sql.DB, provider providers.RevokeProvider) *TokenRevoker {
	// Create a new context
	ctx := context.Background()
	// Create a new context, with its cancellation function
	// from the original context
	// ctx, cancel := context.WithCancel(ctx)

	return &TokenRevoker{
		db:       db,
		provider: provider,
		requests: make(chan RevokeRequest, 2),
		ctx:      ctx,
		// tokenChans: []chan *oauth2.Token{},
		// errChans:   []chan error{},
	}
}

type TokenRevoker struct {
	db       *sql.DB
	provider providers.RevokeProvider
	requests chan RevokeRequest
	ctx      context.Context
}

func (tr *TokenRevoker) Start() {
	go func() {
		tr.Listen()
	}()
}

func (tr *TokenRevoker) Listen() {
	// saving the token to a tokens map[string]*oauth2.Token based on the
	// parameters for the db query could make it faster?
	for {
		select {
		case request := <-tr.requests:
			resp, err := tr.revoke(request)
			tr.handleResults(request, resp, err)
		case <-tr.ctx.Done():
			fmt.Println("done")
			return
			// default:
			// 	fmt.Println("default")
			// 	return
		}
	}
}

func (tr *TokenRevoker) Revoke(params TokenRevokeParams, events *GrafanaEvents, hub *sentry.Hub) (*http.Response, error) {
	request := tr.NewTokenRevoke(params, events, hub)
	tr.requests <- request

	// block on both channels
	// this must keep waiting until the worker is done: the worker writes to
	// events and hub and the caller sends them after this returns
	result := <-request.result
	close(request.result)
	return result.response, errors.WithStack(result.err)
}

func (tr *TokenRevoker) revoke(request RevokeRequest) (*http.Response, error) {
	i, ok := tr.provider.(providers.RevokeProvider)
	if !ok {
		return nil, errors.Errorf("provider %s does not implement RevokeRoute", tr.provider.Name())
	}

	// custom http client
	client := &http.Client{Timeout: tokenRevokeTimeout}
	rt := NewRoundTripperWithSave(http.DefaultTransport)
	client.Transport = rt
	ctx := context.WithValue(context.TODO(), oauth2.HTTPClient, client)

	// callers only know the original refresh token (CSI-2200), while the
	// provider only accepts the current one after a rotation: look up the
	// row by either and revoke its current refresh token at the provider.
	// token_type_hint is optional (RFC 7009): without it the token can be
	// either a refresh token or an access token
	token := request.params.Token
	hint := request.params.TokenTypeHint
	var dbToken *mysql.OauthToken
	var trx *sql.Tx
	if (hint == "refresh_token" || hint == "") && token != "" {
		var err error
		trx, err = tr.db.BeginTx(ctx, nil)
		if err != nil {
			return nil, errors.WithStack(err)
		}
		// The lookup uses FOR UPDATE, just like the refresh worker. Keep its
		// row lock until the provider call and expiration update are complete.
		defer trx.Rollback()
		dbToken, err = mysql.OauthTokenByAppClientIDClientSecretRefreshTokenOrOriginalRefreshToken(ctx, trx, tr.provider.Name(), request.params.ClientID, request.params.ClientSecret, token)
		request.events.QueueSecretRead(tr.provider.Name(), "")
		if err != nil && errors.Cause(err) != sql.ErrNoRows {
			return nil, errors.WithStack(err)
		}
		if dbToken == nil {
			// Release the connection before the access-token fallback, which
			// uses tr.db (the server may have only one connection available).
			if err := trx.Rollback(); err != nil {
				return nil, errors.WithStack(err)
			}
			trx = nil
		}
		if dbToken != nil && dbToken.RefreshToken != "" {
			token = string(dbToken.RefreshToken)
		}
		if dbToken != nil {
			setSentryTokenID(request.hub, dbToken.ID)
		}
	}

	data := url.Values{
		"token":           []string{token},
		"token_type_hint": []string{request.params.TokenTypeHint},
	}

	// client credentials from the form values (instead of the authorization
	// header, which is passed on below) have to be sent to the provider too
	if request.params.Request.Header.Get("Authorization") == "" && request.params.ClientID != "" {
		data.Set("client_id", request.params.ClientID)
		data.Set("client_secret", request.params.ClientSecret)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, i.RevokeURL(), strings.NewReader(data.Encode()))
	if err != nil {
		return nil, errors.WithStack(err)
	}

	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	// pickup original headers
	req.Header = request.params.Request.Header

	resp, err := client.Do(req)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	if resp.StatusCode == http.StatusOK && request.params.Token != "" {
		if dbToken != nil {
			err = mysql.ExpireRefreshTokenByID(ctx, trx, dbToken.ID, time.Now())
			if err == nil {
				err = trx.Commit()
			}
			request.events.QueueSecretRevoked(dbToken.App, dbToken.GrantType)
			if err != nil {
				resp.Body.Close()
				return nil, errors.WithStack(err)
			}
		} else if hint == "access_token" || hint == "" {
			// Match the access token at update time, so a concurrent rotation
			// cannot be overwritten or have its new access token expired.
			err := mysql.ExpireAccessTokensByAppClientIDAccessToken(ctx, tr.db, tr.provider.Name(), request.params.ClientID, request.params.Token, time.Now())
			// the grant type isn't known without reading the rows
			request.events.QueueSecretRevoked(tr.provider.Name(), "")
			if err != nil {
				resp.Body.Close()
				return nil, errors.WithStack(err)
			}
		}
	}

	return resp, errors.WithStack(err)
}

func (tr *TokenRevoker) handleResults(request RevokeRequest, resp *http.Response, err error) {
	result := TokenRevokeResult{
		response: resp,
		err:      err,
	}
	request.result <- result
}

type RevokeRequest struct {
	events *GrafanaEvents
	hub    *sentry.Hub
	params TokenRevokeParams
	result chan TokenRevokeResult
}

type TokenRevokeResult struct {
	response *http.Response
	err      error
}

type TokenRevokeParams struct {
	ClientID     string `schema:"client_id"`
	ClientSecret string `schema:"client_secret"`

	Token         string `schema:"token"`
	TokenTypeHint string `schema:"token_type_hint"`
	Request       *http.Request
}

func (tr *TokenRevoker) NewTokenRevoke(params TokenRevokeParams, events *GrafanaEvents, hub *sentry.Hub) RevokeRequest {
	return RevokeRequest{
		events: events,
		hub:    hub,
		params: params,
		result: make(chan TokenRevokeResult, 1),
	}
}
