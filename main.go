package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"crypto/tls"
	"net/http"

	"github.com/go-logr/logr"
	"github.com/go-logr/stdr"
	stdlog "log"
)

var (
	Log logr.Logger
)

func main() {
	var tlscert, tlskey string
	var port, verbosity int
	flag.StringVar(&tlscert, "tlsCertFile", "/etc/certs/tls.crt", "File containing the x509 Certificate for HTTPS.")
	flag.StringVar(&tlskey, "tlsKeyFile", "/etc/certs/tls.key", "File containing the x509 private key to --tlsCertFile.")
	flag.IntVar(&port, "port", 8443, "Port to serve on.")
	flag.IntVar(&verbosity, "verbosity", 0, "Verbosity level.")

	flag.Parse()
	stdr.SetVerbosity(verbosity)
	Log = stdr.NewWithOptions(stdlog.New(os.Stdout, "", stdlog.LstdFlags), stdr.Options{LogCaller: stdr.All}).WithName("webhook")

	certs, err := tls.LoadX509KeyPair(tlscert, tlskey)
	if err != nil {
		Log.Error(err, "failed to load certificate", "cert", tlscert, "key", tlskey)
	}

	server := http.Server{
		Addr:      fmt.Sprintf(":%d", port),
		TLSConfig: &tls.Config{Certificates: []tls.Certificate{certs}},
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/validate", validateHandler)
	server.Handler = mux

	go func() {
		if err := server.ListenAndServeTLS("", ""); err != nil {
			Log.Error(err, "Failed to start webserver")
			panic(fmt.Errorf("Failed to start web server: %w", err))
		}
	}()

	c := make(chan os.Signal, 1)
	signal.Notify(c, syscall.SIGINT, syscall.SIGTERM)
	<-c

	Log.Info("Got shutdown, shutting down web server")
	server.Shutdown(context.Background())
}
