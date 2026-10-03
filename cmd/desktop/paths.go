package main

import (
	"os"
	"path/filepath"
	"time"
)

// exeDir is the directory the executable lives in, which is where the client
// keeps its configuration, logs and window profile: one folder, nothing
// scattered.
func exeDir() string {
	exe, err := os.Executable()
	if err != nil {
		if wd, err2 := os.Getwd(); err2 == nil {
			return wd
		}
		return "."
	}
	return filepath.Dir(exe)
}

func defaultConfigPath() string { return filepath.Join(exeDir(), "config.json") }

func nowStamp() string { return time.Now().Format("2006-01-02 15:04:05") }
