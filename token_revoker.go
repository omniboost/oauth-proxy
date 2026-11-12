package oauthproxy

import (
	"context"
	"database/sql"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

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

func (tr *TokenRevoker) Revoke(params TokenRevokeParams) (*http.Response, error) {
	request := tr.NewTokenRevoke(params)
	tr.requests <- request

	// block on both channels
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
	if (hint == "refresh_token" || hint == "") && token != "" {
		var err error
		dbToken, err = mysql.OauthTokenByAppClientIDClientSecretRefreshTokenOrOriginalRefreshToken(ctx, tr.db, tr.provider.Name(), request.params.ClientID, request.params.ClientSecret, token)
		if err != nil && errors.Cause(err) != sql.ErrNoRows {
			return nil, errors.WithStack(err)
		}
		if dbToken != nil && dbToken.RefreshToken != "" {
			token = string(dbToken.RefreshToken)
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
			expiresAt := time.Now()
			dbToken.RefreshTokenExpiresAt = sql.NullTime{Time: expiresAt, Valid: true}
			err = dbToken.Save(ctx, tr.db)
			if err != nil {
				return nil, errors.WithStack(err)
			}
		} else if hint == "access_token" || hint == "" {
			tokens, err := mysql.OauthTokensByAppClientIDAccessToken(ctx, tr.db, tr.provider.Name(), request.params.ClientID, request.params.Token)
			if err != nil {
				return nil, errors.WithStack(err)
			}

			// expire tokens
			for _, t := range tokens {
				expiresAt := time.Now()
				t.ExpiresAt = sql.NullTime{Time: expiresAt, Valid: true}
				err := t.Save(ctx, tr.db)
				if err != nil {
					return nil, errors.WithStack(err)
				}
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

func (tr *TokenRevoker) NewTokenRevoke(params TokenRevokeParams) RevokeRequest {
	return RevokeRequest{
		params: params,
		result: make(chan TokenRevokeResult, 1),
	}
}
