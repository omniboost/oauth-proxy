package oauthproxy

import (
	"context"
	"database/sql"
	"fmt"
	"log"

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
	go tr.Listen()
}

func (tr *TokenRequester) Listen() {
	var token *oauth2.Token
	var err error

	handleResults := func(request TokenRequest, token *oauth2.Token, err error) {
		log.Println("handleresult")
		result := TokenRequestResult{
			token: token,
			err:   err,
		}
		log.Println("HIEROOO")
		request.result <- result
	}

	for {
		fmt.Println("foooooooooooooooooooooor")
		select {
		case request := <-tr.requests:
			fmt.Println("new request")
			params := request.params
			if token == nil {
				token, err = tr.TokenFromDB(params)
				fmt.Println("2")
				if err == sql.ErrNoRows {
					// no results in db: request new token
					token, err = tr.FetchNewToken(params)
					fmt.Println("3")
					if err != nil {
						handleResults(request, token, err)
						return
					}

					err = tr.SaveToken(token, params)
					fmt.Println("4")
					if err != nil {
						handleResults(request, token, err)
						return
					}

					// have token and is saved: continue flow
				} else if err != nil {
					// error requesting token from db
					fmt.Println("6")
					handleResults(request, token, err)
					return
				}
			}

			fmt.Println("7")
			log.Printf("%+v", token)
			// existing token, check if still valid
			if token.Valid() {
				handleResults(request, token, nil)
				return
			}

			fmt.Println("8")
			token, err = tr.FetchNewToken(params)
			if err != nil {
				handleResults(request, token, err)
				return
			}

			fmt.Println("9")
			err = tr.SaveToken(token, params)
			if err != nil {
				handleResults(request, token, err)
				return
			}

			fmt.Println("10")
			// existing token, not valid
			handleResults(request, token, err)
			return

		case <-tr.ctx.Done():
			fmt.Println("done")
			return
		default:
			fmt.Println("default")
			return
		}
	}

	log.Println("ENNDDD")
}

func (tr *TokenRequester) Stop() {
	// ??
}

func (tr *TokenRequester) Request(params providers.TokenRequestParams) (*oauth2.Token, error) {
	request := tr.NewTokenRequest(params)
	log.Println("AAAA")
	log.Println(len(tr.requests))
	tr.requests <- request
	log.Println("BBBBB")

	// block on both channels
	result := <-request.result
	// close(request.result)
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
	dbToken, err := db.OauthTokenByAppClientIDClientSecretOriginalRefreshToken(tr.db, tr.provider.Name(), params.ClientID, params.ClientSecret, params.RefreshToken)
	if err != nil {
		return err
	}

	dbToken.App = tr.provider.Name()
	dbToken.Type = token.Type()
	dbToken.ClientID = params.ClientID
	dbToken.ClientSecret = params.ClientSecret
	dbToken.OriginalRefreshToken = params.RefreshToken
	dbToken.RefreshToken = token.RefreshToken
	dbToken.AccessToken = token.AccessToken
	dbToken.ExpiresAt = xoutil.SqTime{token.Expiry}
	dbToken.CreatedAt = dbToken.CreatedAt
	dbToken.UpdatedAt = dbToken.UpdatedAt
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
