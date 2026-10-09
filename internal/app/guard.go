package app

import "runtime/debug"

// guardTick runs one iteration of a long-lived background loop and turns a panic
// into a log line instead of a dead process.
//
// The node watcher, the subscription scheduler and the process sampler run for
// the whole life of the client, unattended. A nil map or an out-of-range index
// in one of their ticks used to end the process: the user loses the tunnel, the
// tray and the console at once, over a bug the next tick would not have
// repeated. The panic is reported with its stack so it stays diagnosable, and
// the loop keeps going.
func (a *App) guardTick(name string, fn func()) {
	defer func() {
		if r := recover(); r != nil && a.log != nil {
			a.log.Errorf("后台任务 %s 出错，已跳过本次：%v\n%s", name, r, debug.Stack())
		}
	}()
	fn()
}
