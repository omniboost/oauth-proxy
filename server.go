package oauthproxy

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"time"

	"bitbucket.org/tim_online/oauth-proxy/providers"
	"github.com/gorilla/mux"
)

func NewServer() *Server {
	s := &Server{
		router: nil,
		http: &http.Server{
			Addr: "0.0.0.0:8080",
			// Good practice to set timeouts to avoid Slowloris attacks.
			WriteTimeout: time.Second * 15,
			ReadTimeout:  time.Second * 15,
			IdleTimeout:  time.Second * 60,
			Handler:      nil, // Pass our instance of gorilla/mux in.
		},
	}
	s.SetRouter(s.NewRouter())
	return s
}

type Server struct {
	router    *mux.Router
	http      *http.Server
	providers providers.Providers
}

func (s *Server) NewRouter() *mux.Router {
	r := mux.NewRouter()

	for _, prov := range s.providers {
		r.HandleFunc(prov.Route(), s.NewProviderHandler(&prov))
	}
	return r
}

func (s *Server) SetRouter(r *mux.Router) {
	s.router = r
	s.http.Handler = r
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
	s.http.Shutdown(ctx)
	// Optionally, you could run srv.Shutdown in a goroutine and block on
	// <-ctx.Done() if your application should wait for other services
	// to finalize based on context cancellation.
	return nil
}

// func (s *Server) tokenHandler(w http.ResponseWriter, r *http.Request) {
// 	vars := mux.Vars(r)
// 	w.WriteHeader(http.StatusOK)
// 	fmt.Fprintf(w, "App: %v\n", vars["app"])
// }

func (s *Server) NewProviderHandler(provider *providers.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "App: %v\n", provider)
	}
}
