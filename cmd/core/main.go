// Command core is the syan-clash proxy core: local SOCKS5 + HTTP inbounds, an
// ordered rule engine, a pluggable outbound, and a loopback control API that
// also serves the bundled web UI.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"vvpn/internal/app"
	"vvpn/internal/autostart"
	"vvpn/internal/control"
	"vvpn/internal/core"
	"vvpn/internal/tray"
)

var version = "0.2.1"

func main() {
	cfgPath := flag.String("config", "config.json", "path to the configuration file")
	showVersion := flag.Bool("version", false, "print the version and exit")
	renderCore := flag.String("render-core", "", "compile the profile for this core and print its native config")
	profilePath := flag.String("profile", "", "profile JSON to compile when -render-core is used")
	allowMulti := flag.Bool("allow-multi", false, "allow a second instance (skips the single-instance guard)")
	noTray := flag.Bool("no-tray", false, "do not create a notification-area icon")
	refreshSubs := flag.Bool("refresh-subscriptions", true, "refresh saved subscriptions shortly after start")
	subInterval := flag.Duration("subscription-interval", 0, "periodically refresh subscriptions (0 disables)")
	flag.Parse()

	if *showVersion {
		fmt.Println("syan-clash", version)
		return
	}

	if *renderCore != "" {
		profile := core.DefaultProfile()
		if *profilePath != "" {
			raw, err := os.ReadFile(*profilePath)
			if err != nil {
				fmt.Fprintln(os.Stderr, "syan-clash: read profile:", err)
				os.Exit(1)
			}
			if err := json.Unmarshal(raw, &profile); err != nil {
				fmt.Fprintln(os.Stderr, "syan-clash: parse profile:", err)
				os.Exit(1)
			}
		}
		out, err := core.Render(*renderCore, profile)
		if err != nil {
			fmt.Fprintln(os.Stderr, "syan-clash: render:", err)
			os.Exit(1)
		}
		_, _ = os.Stdout.Write(out)
		return
	}

	if !*allowMulti {
		ok, err := autostart.AcquireSingleInstance("syan-clash-console")
		if err != nil {
			fmt.Fprintln(os.Stderr, "syan-clash: single-instance check failed:", err)
		} else if !ok {
			fmt.Fprintf(os.Stderr, "syan-clash: another instance is already running%s\n", apiHint(*cfgPath))
			os.Exit(2)
		}
		defer autostart.ReleaseSingleInstance()
	}

	a, err := app.New(*cfgPath, version)
	if err != nil {
		fmt.Fprintln(os.Stderr, "syan-clash: startup failed:", err)
		os.Exit(1)
	}
	defer a.Stop()

	st := a.Status()
	fmt.Printf("syan-clash %s\n", version)
	fmt.Printf("  socks5 inbound : %s\n", st.SOCKS5Addr)
	fmt.Printf("  http inbound   : %s\n", st.HTTPAddr)
	fmt.Printf("  outbound       : %s (%s)\n", st.Outbound, st.OutboundName)
	fmt.Printf("  rules          : %d\n", st.RuleCount)
	fmt.Printf("  control API    : http://%s/\n", a.Config().API.Addr)
	fmt.Println("press Ctrl+C to stop")

	startupCtx, stopStartup := context.WithCancel(context.Background())
	defer stopStartup()
	a.StartupTasks(startupCtx, app.StartupOptions{
		UpdateSubscriptions:  *refreshSubs,
		SubscriptionInterval: *subInterval,
	})
	// Feeding the process picker from live connections: short-lived connections
	// vanish before the user opens the UI, so sampling has to happen on its own.
	a.StartProcessSampler(startupCtx, 2*time.Second)

	// 退出 from the tray (or from the UI) stops the whole program, exactly
	// like Ctrl+C does.
	quit := make(chan struct{})
	var quitOnce sync.Once
	requestQuit := func() { quitOnce.Do(func() { close(quit) }) }
	a.SetQuitFunc(requestQuit)

	// The tray is optional: a headless or service session simply does not get
	// one, and everything else keeps working.
	if !*noTray && tray.Available() {
		go a.RunTray(context.Background(), st.HTTPAddr, nil, requestQuit)
	}

	srv := &http.Server{
		Addr:              a.Config().API.Addr,
		Handler:           control.New(a).Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}
	errc := make(chan error, 1)
	go func() {
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errc <- err
		}
	}()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)

	select {
	case err := <-errc:
		fmt.Fprintln(os.Stderr, "syan-clash: control API failed:", err)
	case s := <-sig:
		fmt.Printf("\nsyan-clash: received %s, shutting down\n", s)
	case <-quit:
		fmt.Println("\nsyan-clash: quit requested, shutting down")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = srv.Shutdown(ctx)
}

// apiHint reads the configured control address so the "already running" message
// can point the user at the right console.
func apiHint(cfgPath string) string {
	abs, err := filepath.Abs(cfgPath)
	if err != nil {
		abs = cfgPath
	}
	return " (configuration: " + abs + ")"
}
