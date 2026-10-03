package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
)

// When built with -H=windowsgui there is no console, so a failure would
// otherwise be invisible: the window simply never appears with no explanation.
// Everything printed before the UI is up also goes to a log file next to the
// executable.
const logName = "syan-clash-startup.log"

func initStartupLog() func() {
	path := filepath.Join(exeDir(), logName)
	// Append, never truncate: a second double-click must not wipe the log of
	// the instance that is already running.
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return func() {}
	}
	stamp := fmt.Sprintf("=== syan-clash %s  %s  pid=%d ===\n", version, nowStamp(), os.Getpid())
	_, _ = f.WriteString(stamp)
	// Both streams go to the file; in GUI mode there is no console at all.
	r, w, err := os.Pipe()
	if err != nil {
		return func() { _ = f.Close() }
	}
	origOut, origErr := os.Stdout, os.Stderr
	os.Stdout, os.Stderr = w, w
	go func() {
		_, _ = io.Copy(logTee{f: f, console: origOut}, r)
	}()
	return func() {
		_, _ = w.WriteString("\n=== syan-clash 退出 ===\n")
		_ = w.Close()
		// The copier goroutine moves the pipe tail into the file; give it a
		// moment so the exit marker is not lost when the process returns.
		time.Sleep(120 * time.Millisecond)
		os.Stdout, os.Stderr = origOut, origErr
		_ = f.Close()
	}
}

// logTee writes everything to the log file and mirrors it to the console when
// one exists. The console write is best-effort on purpose: a GUI process has
// no console handle, and an error there must not stop the log from being
// written - an io.MultiWriter would return that error and kill the copier, so
// every line after startup (including the exit marker) would be lost.
type logTee struct {
	f       *os.File
	console *os.File
}

func (t logTee) Write(p []byte) (int, error) {
	n, err := t.f.Write(p)
	if t.console != nil {
		_, _ = t.console.Write(p)
	}
	return n, err
}

func logFatal(cleanup func(), format string, args ...any) {
	fmt.Printf(format, args...)
	fmt.Println()
	if cleanup != nil {
		cleanup()
	}
	os.Exit(1)
}
