package main

// A second double-click has to reach the window of the instance that is
// already running, and that instance is not necessarily on the address this
// launch was handed: 127.0.0.1:3090 is the default for every launch, so the
// first instance may have found it taken and slid to the next free port. The
// address it actually bound is therefore published next to the configuration
// file and read back by the next launch.
//
// The record is a hint, never an authority: the caller still has to get a
// successful reply from the address, so a stale file can only cost one failed
// request - it can never make the client act on a dead address.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"time"

	"vvpn/internal/sysproxy"
)

// runtimeAddrName sits beside config.json, the same place the system proxy
// snapshot keeps its state.
const runtimeAddrName = "runtime.json"

type runtimeAddrRecord struct {
	PID     int    `json:"pid"`
	Console string `json:"console"`
	Started string `json:"started"`
}

// runtimeAddrPath is empty when there is no configuration file to sit next to,
// which turns the whole mechanism off rather than guessing a location.
func runtimeAddrPath(cfgPath string) string {
	if cfgPath == "" {
		return ""
	}
	return filepath.Join(filepath.Dir(cfgPath), runtimeAddrName)
}

// publishRuntimeAddr records the console address this process bound and returns
// the function that withdraws the record again - and only when the record is
// still this process's, so a later instance is never unregistered by an
// earlier one shutting down.
func publishRuntimeAddr(cfgPath, consoleAddr string) func() {
	path := runtimeAddrPath(cfgPath)
	if path == "" || consoleAddr == "" {
		return func() {}
	}
	rec := runtimeAddrRecord{
		PID:     os.Getpid(),
		Console: consoleAddr,
		Started: time.Now().Format(time.RFC3339),
	}
	blob, err := json.Marshal(rec)
	if err != nil {
		return func() {}
	}
	if err := os.WriteFile(path, append(blob, '\n'), 0o644); err != nil {
		// A read-only folder next to the exe is not fatal: the client runs,
		// only the "surface the running window" shortcut loses its hint.
		return func() {}
	}
	return func() {
		if cur, ok := readRuntimeAddr(path); ok && cur.PID == rec.PID {
			_ = os.Remove(path)
		}
	}
}

// liveRuntimeAddr is the console address of the instance that published the
// record, or "" when there is nothing worth trying. A record whose process is
// gone is a leftover from a kill, and ignoring it is what keeps the second
// launch from waiting on a port nobody owns any more.
func liveRuntimeAddr(cfgPath string) string {
	rec, ok := readRuntimeAddr(runtimeAddrPath(cfgPath))
	if !ok || rec.Console == "" {
		return ""
	}
	if !sysproxy.OwnerAlive(rec.PID) {
		return ""
	}
	return rec.Console
}

func readRuntimeAddr(path string) (runtimeAddrRecord, bool) {
	if path == "" {
		return runtimeAddrRecord{}, false
	}
	blob, err := os.ReadFile(path)
	if err != nil {
		return runtimeAddrRecord{}, false
	}
	var rec runtimeAddrRecord
	if err := json.Unmarshal(blob, &rec); err != nil {
		return runtimeAddrRecord{}, false
	}
	return rec, true
}
