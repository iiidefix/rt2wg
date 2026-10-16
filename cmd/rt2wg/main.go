// Command rt2wg keeps WireGuard peer AllowedIPs in sync with the kernel
// routing table. It is configured only through environment variables.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"golang.zx2c4.com/wireguard/wgctrl"

	"rt2wg/internal/config"
	"rt2wg/internal/daemon"
	"rt2wg/internal/tables"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "rt2wg: %v\n", err)
		os.Exit(1)
	}
}

// env returns the variable's value, or def when it is unset or empty.
func env(name, def string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return def
}

func run() error {
	iface := env("WG_INTERFACE", "wg0")
	confPath := env("WG_CONF_PATH", "/etc/wireguard/"+iface+".conf")
	level := slog.LevelInfo
	if strings.EqualFold(os.Getenv("LOG_LEVEL"), "debug") {
		level = slog.LevelDebug
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level})).
		With("iface", iface)

	ts, err := tables.Parse(os.Getenv("WG_ROUTE_TABLES"), "/")
	if err != nil {
		return fmt.Errorf("WG_ROUTE_TABLES: %w", err)
	}
	wg, err := wgctrl.New()
	if err != nil {
		return fmt.Errorf("opening wgctrl: %w", err)
	}
	defer wg.Close()
	if _, err := wg.Device(iface); errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("%s: no such WireGuard device", iface)
	} else if err != nil {
		return fmt.Errorf("reading WireGuard device %s: %w", iface, err)
	}
	cfg, err := config.Load(confPath)
	if err != nil {
		return err
	}
	log.Info("config loaded", "path", confPath, "peers", len(cfg.Peers))
	log.Info("monitored tables", "tables", ts.String())

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)

	daemon.New(iface, confPath, ts, cfg, wg, log).Run(ctx, hup)
	return nil
}
