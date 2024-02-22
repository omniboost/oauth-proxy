package oauthproxy

import (
	"context"
	"database/sql"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/omniboost/oauth-proxy/db"
	"github.com/omniboost/oauth-proxy/providers"
	"github.com/pkg/errors"
	"golang.org/x/oauth2"
)

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
	client := &http.Client{}
	rt := NewRoundTripperWithSave(http.DefaultTransport)
	client.Transport = rt
	ctx := context.WithValue(context.TODO(), oauth2.HTTPClient, client)

	data := url.Values{
		"token":           []string{request.params.Token},
		"token_type_hint": []string{request.params.TokenTypeHint},
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
		if request.params.TokenTypeHint == "refresh_token" {
			token, err := db.OauthTokenByAppRefreshToken(ctx, tr.db, tr.provider.Name(), request.params.Token)
			expiresAt := db.NewTime(time.Now())
			token.RefreshTokenExpiresAt = &expiresAt
			err = token.Save(ctx, tr.db)
			if err != nil {
				return nil, errors.WithStack(err)
			}
		} else if request.params.TokenTypeHint == "access_token" {
			tokens, err := db.OauthTokensByAppAccessToken(ctx, tr.db, tr.provider.Name(), request.params.Token)
			if err != nil {
				return nil, errors.WithStack(err)
			}

			// expire tokens
			for _, t := range tokens {
				expiresAt := db.NewTime(time.Now())
				t.ExpiresAt = &expiresAt
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
