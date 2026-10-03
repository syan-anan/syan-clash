package service

import (
	"errors"
	"os"
	"testing"
	"time"
)

// childEnv 让测试二进制把自己当成一个长命子进程跑起来。
const childEnv = "SYANV_SERVICE_TEST_CHILD"

// TestMain 兼做子进程入口。用例需要的是一个活着的子进程，而不是一个立刻
// 退出的进程，所以子进程模式直接睡下去，由 Stop() 负责结束它。
func TestMain(m *testing.M) {
	if os.Getenv(childEnv) == "1" {
		time.Sleep(120 * time.Second)
		os.Exit(0)
	}
	os.Exit(m.Run())
}

// testBinary 返回当前测试二进制的绝对路径，Start 要的就是可执行文件本身。
func testBinary(t *testing.T) string {
	t.Helper()
	if exe, err := os.Executable(); err == nil {
		return exe
	}
	return os.Args[0]
}

// startTestChild 起一个测试子进程。Start 不接受环境变量，所以让子进程从
// 父进程继承这个标记，TestMain 才能认出自己该扮演子进程。
func startTestChild(t *testing.T, r *Runner, id string) Proc {
	t.Helper()
	t.Setenv(childEnv, "1")
	p, err := r.Start(id, testBinary(t), nil, "")
	if err != nil {
		t.Fatalf("Start(%q) 失败：%v", id, err)
	}
	return p
}

func TestStartRunsAChild(t *testing.T) {
	r := NewRunner(nil)
	defer r.StopAll()

	p := startTestChild(t, r, "child")
	if p.PID <= 0 {
		t.Fatalf("Start 返回的 PID = %d，想要 > 0", p.PID)
	}
	got, ok := r.Get("child")
	if !ok {
		t.Fatal("Get 找不到刚启动的进程")
	}
	if got.PID != p.PID {
		t.Fatalf("Get 的 PID = %d，Start 的 PID = %d", got.PID, p.PID)
	}
	if got.Exited {
		t.Fatal("刚启动的进程被判定为已退出")
	}
	if list := r.List(); len(list) != 1 || list[0].ID != "child" {
		t.Fatalf("List = %+v，想要只有一条 child", list)
	}

	if err := r.Stop("child"); err != nil {
		t.Fatalf("Stop 失败：%v", err)
	}
	after, ok := r.Get("child")
	if !ok {
		t.Fatal("Stop 之后 Get 找不到进程")
	}
	if !after.Exited {
		t.Fatal("Stop 之后 Exited 仍为 false")
	}
}

func TestStartTwiceReturnsErrRunning(t *testing.T) {
	r := NewRunner(nil)
	defer r.StopAll()

	startTestChild(t, r, "dup")
	t.Setenv(childEnv, "1")
	if _, err := r.Start("dup", testBinary(t), nil, ""); !errors.Is(err, ErrRunning) {
		t.Fatalf("第二次 Start 的错误 = %v，想要 ErrRunning", err)
	}
}

func TestStopMissingIsIdempotent(t *testing.T) {
	r := NewRunner(nil)
	if err := r.Stop("nope"); err != nil {
		t.Fatalf("Stop(未知 id) = %v，想要 nil", err)
	}
}

func TestStartRejectsEmptyIDAndExe(t *testing.T) {
	r := NewRunner(nil)
	if _, err := r.Start("", testBinary(t), nil, ""); err == nil {
		t.Fatal("空 id 应该报错")
	}
	if _, err := r.Start("x", "", nil, ""); err == nil {
		t.Fatal("空 exe 应该报错")
	}
}
