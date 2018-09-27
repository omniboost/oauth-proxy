package oauthproxy

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"time"

	"bitbucket.org/tim_online/oauth-proxy/providers"
	"github.com/gorilla/mux"
	"github.com/pkg/errors"
	"github.com/xo/dburl"
	"golang.org/x/oauth2"
)

func NewServer() (*Server, error) {
	s := &Server{}

	db, err := s.NewDB()
	if err != nil {
		return s, err
	}
	s.SetDB(db)

	s.SetHTTP(s.NewHTTP())

	// providers depends on db
	s.SetProviders(s.NewProviders())

	// router depends on providers
	s.SetRouter(s.NewRouter())

	return s, nil
}

type Server struct {
	port int

	router          *mux.Router
	http            *http.Server
	db              *sql.DB
	providers       providers.Providers
	tokenRequesters map[string]*TokenRequester
}

func (s *Server) NewHTTP() *http.Server {
	return &http.Server{
		Addr: s.Addr(),
		// Good practice to set timeouts to avoid Slowloris attacks.
		WriteTimeout: time.Second * 15,
		ReadTimeout:  time.Second * 15,
		IdleTimeout:  time.Second * 60,
		Handler:      s.router, // Pass our instance of gorilla/mux in.
	}
}

func (s *Server) SetHTTP(http *http.Server) {
	s.http = http
}

func (s *Server) NewProviders() providers.Providers {
	return providers.Load()
}

func (s *Server) SetProviders(providers providers.Providers) {
	s.providers = providers

	s.tokenRequesters = map[string]*TokenRequester{}
	for _, provider := range providers {
		tr := NewTokenRequester(s.db, provider)
		s.tokenRequesters[provider.Name()] = tr
		tr.Start()
	}
}

func (s *Server) NewRouter() *mux.Router {
	r := mux.NewRouter()

	for _, prov := range s.providers {
		r.HandleFunc(prov.Route(), s.NewProviderHandler(prov))
	}
	return r
}

func (s *Server) SetRouter(r *mux.Router) {
	s.router = r
	s.http.Handler = r
}

func (s *Server) SetPort(port int) {
	s.port = port
	// also update http server listen address
	s.http.Addr = s.Addr()
}

func (s *Server) Addr() string {
	return fmt.Sprintf("0.0.0.0:%d", s.port)
}

func (s *Server) NewDB() (*sql.DB, error) {
	return dburl.Open("sqlite://db/production.sqlite3?loc=auto")
}

func (s *Server) SetDB(db *sql.DB) {
	s.db = db
}

func (s *Server) Start() error {
	errChan := make(chan error, 1)
	// run our server in a goroutine so that it doesn't block.
	go func() {
		if err := s.http.ListenAndServe(); err != nil {
			log.Println(err)
			errChan <- err
		}
	}()

	signalChan := make(chan os.Signal, 1)
	// we'll accept graceful shutdowns when quit via SIGINT (Ctrl+C)
	// SIGKILL, SIGQUIT or SIGTERM (Ctrl+/) will not be caught.
	signal.Notify(signalChan, os.Interrupt)

	// block until we receive a signal or error a select statement blocks until
	// at least one of it’s cases can proceed
	select {
	case <-signalChan:
		break
	case err := <-errChan:
		if err != nil {
			return err
		}
	}

	close(signalChan)
	close(errChan)

	return s.Stop()
}

func (s *Server) Stop() error {
	log.Println("shutting down")

	// the duration for which the server gracefully wait for existing
	// connections to finish - e.g. 15s or 1m"
	wait := time.Second * 15

	// Create a deadline to wait for.
	ctx, cancel := context.WithTimeout(context.Background(), wait)
	defer cancel()

	// Doesn't block if no connections, but will otherwise wait
	// until the timeout deadline.
	// s.http.Shutdown(ctx)

	// Optionally, you could run srv.Shutdown in a goroutine and block on
	// <-ctx.Done() if your application should wait for other services
	// to finalize based on context cancellation.
	go s.http.Shutdown(ctx)
	for _, tr := range s.tokenRequesters {
		tr.Stop()
	}
	<-ctx.Done()
	return nil
}

func (s *Server) NewProviderHandler(provider providers.Provider) http.HandlerFunc {
	// - parse json inline
	// - strip out refresh and access token, grant_type, client_id and
	// client_secret
	// - lookup into db
	// - update refresh token
	// - send to provider endpoint

	// {
	//  	refresh_token: "Gcp7!IAAAABh4eI8DgkxRyGGyHPLLOz3y9Ss …",
	//  	grant_type: "refresh_token",
	//  	client_id: "b81cc4de-d192-400e-bcb4-09254394c52a",
	//  	client_secret: "n3G7KAhcv8OH",
	// }

	return func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()

		// get oauth params from incomming request
		decoder := json.NewDecoder(r.Body)
		reqBody := TokenRequestBody{}
		err := decoder.Decode(&reqBody)
		if err != nil && err != io.EOF {
			s.ErrorResponse(w, err)
			return
		}

		// use reqBody.RefreshToken, reqBody.ClientID & reqBody.ClientSecret to
		// retrieve the latest valid refreshtoken and accesstoken from storage

		// I don't know the format of the returned data for every provider so
		// I have to return the raw data with an updated `expires_in` field

		// Update: can't do that because I don't have access to oauth2.Token.raw
		// Only Token.Extra(string)

		// create a tokenrequest for the provider
		trp := providers.TokenRequestParams{
			ClientID:     reqBody.ClientID,
			ClientSecret: reqBody.ClientSecret,
			RefreshToken: reqBody.RefreshToken,
		}

		token, err := s.RequestToken(provider, trp)
		if err != nil {
			s.ErrorResponse(w, err)
			return
		}

		// create response body
		responseBody := TokenResponseBody{
			TokenType:    token.TokenType,
			AccessToken:  token.AccessToken,
			RefreshToken: token.RefreshToken,
			ExpiresIn:    int(time.Until(token.Expiry).Seconds()),
		}

		// stream response body
		encoder := json.NewEncoder(w)
		encoder.Encode(responseBody)
	}
}

func (s *Server) NewClient() *http.Client {
	return http.DefaultClient
}

func (s *Server) ErrorResponse(w http.ResponseWriter, err error) {
	w.WriteHeader(http.StatusBadRequest)

	// fake original oauth token response
	errorResponse := ErrorResponse{
		Error:            "invalid_request",
		ErrorDescription: strings.TrimPrefix(fmt.Sprint(err), "oauth2: "),
		ErrorURI:         "",
	}

	encoder := json.NewEncoder(w)
	encoder.Encode(errorResponse)
}

func (s *Server) RequestToken(provider providers.Provider, params providers.TokenRequestParams) (*oauth2.Token, error) {
	tr, ok := s.tokenRequesters[provider.Name()]
	if !ok {
		// this should not happen because all tokenrequesters are loaded when
		// Server.SetProviders() is called
		return nil, errors.Errorf("Token requester for provider %s doesn't exist", provider.Name())
	}

	return tr.Request(params)
}
