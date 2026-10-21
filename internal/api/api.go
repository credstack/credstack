package api

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"

	"github.com/credstack/credstack/internal/handler"
	"github.com/credstack/credstack/pkg/config"
	"github.com/gin-gonic/gin"
	"golang.org/x/sys/unix"
)

type Api struct {
	// config The API Configuration options passed at construction
	config *config.ServerConfig

	// router The Gin API router
	router *gin.Engine

	// srv The API Server
	srv *http.Server
}

func (api *Api) handleSignal(ctx context.Context) {
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, unix.SIGTERM, unix.SIGINT)

	for {
		select {
		case <-ctx.Done():
			if err := api.shutdown(ctx); err != nil {
				log.Printf("error on shutdown: %v", err.Error())
			}

			return
		case <-sig:
			log.Printf("received either SIGTERM or SIGINT. Shutting down API Server")
			if err := api.shutdown(ctx); err != nil {
				log.Printf("error on shutdown: %v", err.Error())
			}

			return
		}
	}
}

// shutdown Gracefully stops the API Server
func (api *Api) shutdown(ctx context.Context) error {
	if err := api.srv.Shutdown(ctx); err != nil {
		return fmt.Errorf("failed to shutdown API Server: %v", err.Error())
	}

	return nil
}

// RegisterRouteHandlers Registers a list of route handlers with the API
func (api *Api) RegisterRouteHandlers(handlers ...handler.RouteHandler) {
	for _, h := range handlers {
		h.Group(api.router)
	}
}

// Run Start the API Server and return errors resulting from its execution
func (api *Api) Run(ctx context.Context) error {
	go api.handleSignal(ctx)

	if api.config.ApiConfig.UseTLS {
		if err := api.srv.ListenAndServeTLS(api.config.ApiConfig.TLSCert, api.config.ApiConfig.TLSKey); err != nil {
			return fmt.Errorf("failed to start API Server with TLS: %v", err.Error())
		}

		return nil
	}

	listener, err := net.Listen("tcp", api.config.ApiConfig.Addr())
	if err != nil {
		return fmt.Errorf("failed to create listener: %v", err.Error())
	}

	if err := api.srv.Serve(listener); err != nil {
		return fmt.Errorf("failed to start API Server: %v", err.Error())
	}

	return nil
}

// New Initializes a new Api with the provided Config and returns a pointer to it
func New(config *config.ServerConfig) (*Api, error) {
	if err := config.ApiConfig.Validate(); err != nil {
		return nil, err
	}

	router := gin.Default()
	router.SetTrustedProxies(config.ApiConfig.TrustedIPs)
	router.TrustedPlatform = config.ApiConfig.TrustedPlatform

	// Always initialize the API with recovery middleware. Catches `panic()` mid execution
	router.Use(
		gin.Recovery(),
	)

	gin.SetMode(gin.ReleaseMode)
	if config.ApiConfig.Debug {
		gin.SetMode(gin.DebugMode)
		// TODO: Inject pprof here
	}

	api := &Api{
		config: config,
		router: router,
		srv: &http.Server{
			Handler: router.Handler(),
			Addr:    config.ApiConfig.Addr(),
		},
	}

	if config.ApiConfig.UseTLS {

		// This majority of this is not exposed to the end user as what is defined below represents the
		// most secure options that you can configure. Very few use cases depend on having to change the
		// perferred cipher suites or minimum TLS version as most of these options have been deprecated
		// for quite some time.
		//
		// See here for recommendations around TLS: https://csrc.nist.gov/news/2019/nist-publishes-sp-800-52-revision-2
		api.srv.TLSConfig = &tls.Config{
			MinVersion:       tls.VersionTLS12,
			CurvePreferences: []tls.CurveID{tls.CurveP521, tls.CurveP384, tls.CurveP256},
			CipherSuites: []uint16{
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
				tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_RSA_WITH_AES_256_CBC_SHA,
				tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, // required for HTTP/2
			},
		}
	}

	return api, nil
}
