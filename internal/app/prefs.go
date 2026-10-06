package app

import "vvpn/internal/config"

// The desktop shell's preferences live in the same file as the proxy
// configuration, but nothing in the routing path reads them. Keeping them here
// rather than in a second file is what makes "copy the folder" move the whole
// setup, which is the only backup story a portable client can offer.

// SilentStart reports whether the next launch should go straight to the tray.
func (a *App) SilentStart() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.cfg.App.SilentStart
}

// SetSilentStart records the tray preference.
//
// It deliberately does not go through Reload: the preference changes nothing
// about the listeners, and Reload would tear down and re-bind every inbound
// just to flip a boolean. It writes the file first and only then updates the
// in-memory copy, so a failed write leaves the running client consistent with
// what is on disk.
func (a *App) SetSilentStart(on bool) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.cfg.App.SilentStart == on {
		return nil
	}
	next := a.cfg
	next.App.SilentStart = on
	if err := config.Save(a.cfgPath, next); err != nil {
		return err
	}
	a.cfg = next
	return nil
}

// PresetAutoDone reports whether the built-in default rule bundle has already
// been offered to this install.
func (a *App) PresetAutoDone() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.cfg.App.PresetAuto
}

// markPresetAutoDone records that the default preset has been dealt with. Like
// the other preferences it writes the file before memory, and it never touches
// the listeners: a rules preset has nothing to do with the tunnel.
func (a *App) markPresetAutoDone() {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.cfg.App.PresetAuto {
		return
	}
	next := a.cfg
	next.App.PresetAuto = true
	if err := config.Save(a.cfgPath, next); err != nil {
		a.log.Warnf("\u4fdd\u5b58\u9ed8\u8ba4\u9884\u8bbe\u6807\u8bb0\u5931\u8d25\uff1a%v", err)
		return
	}
	a.cfg = next
}

// UpdateSource is where the client looks for a newer build of itself.
func (a *App) UpdateSource() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.cfg.App.UpdateSource
}

// SetUpdateSource records the update channel. Like SetSilentStart it writes the
// file first and only then updates memory, and it never touches the listeners:
// an update channel has nothing to do with the tunnel.
func (a *App) SetUpdateSource(source string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.cfg.App.UpdateSource == source {
		return nil
	}
	next := a.cfg
	next.App.UpdateSource = source
	if err := config.Save(a.cfgPath, next); err != nil {
		return err
	}
	a.cfg = next
	return nil
}
