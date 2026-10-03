package service

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"sync"
	"time"
)

// ErrRunning 表示同一个 ID 的子进程已经在跑。上层路由要把它映射成 409，
// 所以用哨兵错误，调用方不必去比字符串。
var ErrRunning = errors.New("该进程已经在运行")

// Proc 是一个被服务托管的子进程对外的快照。
type Proc struct {
	ID        string   `json:"id"`
	PID       int      `json:"pid"`
	Exe       string   `json:"exe"`
	Args      []string `json:"args,omitempty"`
	Dir       string   `json:"dir,omitempty"`
	StartedAt string   `json:"started_at"`
	Exited    bool     `json:"exited"`
	ExitCode  int      `json:"exit_code"`
}

// entry 把对外快照和内部句柄绑在一起；cmd 只在包内使用，不参与 JSON。
type entry struct {
	proc Proc
	cmd  *exec.Cmd
}

// Runner 托管子进程。HTTP 服务会并发调用它，而后台的 Wait 协程会写状态，
// 所以每个字段都由 mu 保护。
type Runner struct {
	mu    sync.Mutex
	logf  func(string, ...any)
	procs map[string]*entry
}

// NewRunner 建一个空的管理器；logf 允许为 nil。
func NewRunner(logf func(string, ...any)) *Runner {
	if logf == nil {
		logf = func(string, ...any) {}
	}
	return &Runner{logf: logf, procs: make(map[string]*entry)}
}

// Start 拉起一个子进程后立刻返回，不等它退出。
//
// 检查是否已经在跑、启动、写入新条目必须在同一把锁里完成：否则两个并发请求
// 会同时通过检查，同一个 ID 拉起两个进程。
func (r *Runner) Start(id, exe string, args []string, dir string) (Proc, error) {
	if id == "" {
		return Proc{}, errors.New("缺少 id")
	}
	if exe == "" {
		return Proc{}, errors.New("缺少 exe")
	}

	p := Proc{
		ID:        id,
		Exe:       exe,
		Args:      append([]string(nil), args...),
		Dir:       dir,
		StartedAt: time.Now().Format(time.RFC3339),
	}

	cmd := exec.Command(exe, args...)
	if dir != "" {
		cmd.Dir = dir
	}
	// 服务没有控制台。三个标准流都留在 null 设备上：一旦继承了没人读的管道，
	// 子进程写一行日志就会被内核阻塞住。
	cmd.Stdin = nil
	cmd.Stdout = nil
	cmd.Stderr = nil
	// 无窗口启动是本项目的硬约束：服务跑在会话 0，子进程一旦露出窗口，
	// 就是用户桌面上一闪而过的幽灵弹窗。
	cmd.SysProcAttr = sysProcAttr()

	r.mu.Lock()
	if e, ok := r.procs[id]; ok && !e.proc.Exited {
		r.mu.Unlock()
		return Proc{}, ErrRunning
	}
	if err := cmd.Start(); err != nil {
		r.mu.Unlock()
		return Proc{}, fmt.Errorf("启动 %s 失败：%w", exe, err)
	}
	p.PID = cmd.Process.Pid
	e := &entry{cmd: cmd, proc: p}
	r.procs[id] = e
	r.mu.Unlock()

	r.logf("已启动子进程 id=%s pid=%d exe=%s", id, p.PID, exe)
	go r.reap(id, e)
	return cloneProc(p), nil
}

// reap 在后台等子进程退出并记下退出码，绝不阻塞 Start 的调用方。
func (r *Runner) reap(id string, e *entry) {
	err := e.cmd.Wait()
	code := 0
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			code = ee.ExitCode()
		} else {
			code = -1
		}
	}
	pid := e.proc.PID
	r.mu.Lock()
	e.proc.Exited = true
	e.proc.ExitCode = code
	r.mu.Unlock()
	r.logf("子进程已退出 id=%s pid=%d code=%d", id, pid, code)
}

// Stop 结束该 ID 的子进程。幂等：未知 ID、已经退出的进程都返回 nil。
func (r *Runner) Stop(id string) error {
	r.mu.Lock()
	e, ok := r.procs[id]
	if !ok || e.proc.Exited {
		r.mu.Unlock()
		return nil
	}
	proc := e.cmd.Process
	r.mu.Unlock()

	if proc == nil {
		return nil
	}
	// 只结束我们自己 Start 出来的那个 pid。服务是 LocalSystem，按镜像名杀进程
	// 会连带干掉用户手工启动的同名程序。
	if err := proc.Kill(); err != nil && !errors.Is(err, os.ErrProcessDone) {
		return fmt.Errorf("结束 %s（pid=%d）失败：%w", id, proc.Pid, err)
	}
	// 等 reap 落状态，这样调用方 Stop 之后立刻 Get 也能看到 Exited=true。
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		r.mu.Lock()
		done := e.proc.Exited
		r.mu.Unlock()
		if done {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	return nil
}

// Get 返回一个进程的快照；不存在时 ok=false。
func (r *Runner) Get(id string) (Proc, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	e, ok := r.procs[id]
	if !ok {
		return Proc{}, false
	}
	return cloneProc(e.proc), true
}

// List 返回全部已知进程（含已经退出的），按 ID 排序，输出稳定便于对比。
func (r *Runner) List() []Proc {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]Proc, 0, len(r.procs))
	for _, e := range r.procs {
		out = append(out, cloneProc(e.proc))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// StopAll 结束全部子进程；服务停止时调用。
func (r *Runner) StopAll() {
	r.mu.Lock()
	ids := make([]string, 0, len(r.procs))
	for id := range r.procs {
		ids = append(ids, id)
	}
	r.mu.Unlock()
	for _, id := range ids {
		_ = r.Stop(id)
	}
}

// cloneProc 复制快照，尤其是 Args 切片：调用方拿到的数据不能和内部状态共享
// 底层数组，否则并发读写会踩到 race。
func cloneProc(p Proc) Proc {
	if p.Args != nil {
		p.Args = append([]string(nil), p.Args...)
	}
	return p
}
