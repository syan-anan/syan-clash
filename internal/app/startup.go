package app

import (
	"context"
	"time"
)

// StartupTasks runs the work that should happen once, shortly after the client
// starts: refresh saved subscriptions and start the core if configured to.
// Failures are logged, never fatal.
func (a *App) StartupTasks(ctx context.Context, opts StartupOptions) {
	// Node-list hygiene goes first: cleaning the airport's own information rows
	// is on by default, and a profile imported by an older build still carries
	// them. Running before the subscription sweep and before anything reads the
	// profile means the core - auto-started or started from the tray - never
	// sees them. It is a no-op once the list is clean.
	a.HealInfoNodes(ctx)
	// The default rule bundle lands before anything else reads the profile, so
	// a fresh client already routes 国内直连 / 国外走节点 without the user having
	// to find the 规则 page. It only ever runs once per install.
	a.ApplyDefaultPresetOnce(ctx)
	if opts.UpdateSubscriptions {
		go func() {
			// Wait for the core to be up so an update can take effect
			// immediately instead of racing with its startup.
			select {
			case <-ctx.Done():
				return
			case <-time.After(3 * time.Second):
			}
			if len(a.Subscriptions()) == 0 {
				return
			}
			// Only the subscriptions that asked for automatic refreshes and
			// whose interval has passed: a switch the user turned off has to
			// mean no background traffic, not "except at startup".
			if n := a.RefreshDueSubscriptions(ctx); n > 0 {
				a.log.Infof("启动任务：刷新 %d 个到期订阅", n)
			}
		}()
	}
	if opts.SubscriptionInterval > 0 {
		a.StartSubscriptionScheduler(ctx, opts.SubscriptionInterval)
	}
	// Keeps the entry point pointed at the running core and the console's
	// "exit" row naming the node traffic really uses.
	a.StartCoreNodeWatcher(ctx, 3*time.Second)
}

// StartupOptions controls the optional startup work.
type StartupOptions struct {
	UpdateSubscriptions  bool
	SubscriptionInterval time.Duration
}
