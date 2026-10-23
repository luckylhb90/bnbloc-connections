// Command bnbloc-connections is the connections component: a bnbloc service
// component that lets a member's own agent reach the systems the member
// connected, as the member (README.md). It runs beside the bnbloc gateway,
// on the operator's network, like any endpoint component.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/luckylhb90/bnbloc-connections/internal/platform"
	"github.com/luckylhb90/bnbloc-connections/internal/service"
)

// Set at build time.
var (
	version = "dev"
	commit  = ""
)

// The environment holds only the bootstrap: where to listen, the gateway,
// the component's install name and credential. Everything else (the
// connectors, their client values, the members' connections) is in
// bnbloc's sealed store.
const (
	envListen   = "BNBLOC_CONNECTIONS_LISTEN"
	envGateway  = "BNBLOC_CONNECTIONS_BNBLOC_URL"
	envName     = "BNBLOC_CONNECTIONS_NAME"
	envSecret   = "BNBLOC_CONNECTIONS_SECRET"
	envBasePath = "BNBLOC_CONNECTIONS_BASE_PATH"
)

func main() {
	if len(os.Args) > 1 && (os.Args[1] == "version" || os.Args[1] == "--version") {
		fmt.Println("bnbloc-connections", version, commit)
		return
	}
	if err := run(); err != nil {
		slog.Error("bnbloc-connections stopped", "error", err)
		os.Exit(1)
	}
}

func run() error {
	listen := envOr(envListen, ":8098")
	gateway := strings.TrimSpace(os.Getenv(envGateway))
	if gateway == "" {
		return errors.New(envGateway + " is required (the bnbloc gateway as this process reaches it)")
	}
	secret := strings.TrimSpace(os.Getenv(envSecret))
	if secret == "" {
		slog.Warn("bnbloc-connections: " + envSecret + " is not set: every call is refused until it is (the credential the install showed once)")
	}
	_ = os.Unsetenv(envSecret)
	svc := &service.Service{
		P:        &platform.Platform{BaseURL: gateway, Name: envOr(envName, "connections"), Secret: secret},
		BasePath: strings.TrimSpace(os.Getenv(envBasePath)),
		Upstream: service.Guarded(),
	}
	srv := &http.Server{Addr: listen, Handler: svc.Handler(), ReadHeaderTimeout: 10 * time.Second}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = srv.Shutdown(sctx)
	}()
	slog.Info("bnbloc-connections listening", "addr", listen, "name", svc.P.Name, "version", version)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

func envOr(k, def string) string {
	if v := strings.TrimSpace(os.Getenv(k)); v != "" {
		return v
	}
	return def
}
