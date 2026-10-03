package control

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"

	"vvpn/internal/app"
	"vvpn/internal/elevate"
	"vvpn/internal/winsvc"
)

// The 设置 page's 「系统与服务」 card (P0-1). Two settings live here:
//
//   - the service itself: install / uninstall / start / stop, plus its state;
//   - the system-proxy guard switch, which until now was implicit (the guard
//     started whenever the system proxy was on) and is now something the user
//     can turn off without turning the proxy off.
//
// Installing a service needs administrator rights. The client is normally
// unprivileged, so the API never tries to escalate on its own: it reports
// "need_admin" and the card offers a button that relaunches this exe with
// -service-install through the UAC prompt. That is one deliberate, user-visible
// prompt on an explicit click - never a background escalation.

// serviceView is the status payload both GET and POST answer with.
type serviceView struct {
	app.ServiceStatus
	// Elevated says whether this process could install the service itself.
	Elevated bool `json:"elevated"`
	// GuardRunning says whether the guard copy of this exe is alive right now,
	// which is what makes the switch below meaningful: "on" while the guard is
	// dead means "it will be started on the next tick".
	GuardRunning bool `json:"guard_running"`
	// Hint is a ready-to-show Chinese sentence for the card.
	Hint string `json:"hint"`
}

func (h *API) buildServiceView() serviceView {
	st := h.app.ServiceStatus()
	v := serviceView{
		ServiceStatus: st,
		Elevated:      elevate.IsElevated(),
		GuardRunning:  h.app.ProxyGuardRunning(),
	}
	switch {
	case !st.Supported:
		v.Hint = "当前平台不支持 Windows 服务，客户端按原样运行。"
	case st.Err != "":
		v.Hint = "读取服务状态失败：" + st.Err
	case !st.Installed:
		v.Hint = "服务未安装。安装后 TUN 等需要管理员权限的操作可以交给服务执行，不必每次提权。"
	case st.Running:
		v.Hint = "服务运行中。"
	default:
		v.Hint = "服务已安装但没有运行。"
	}
	if !v.Elevated && (!st.Installed || !st.Running) {
		v.Hint += " 安装/卸载需要管理员权限，点按钮会弹一次 UAC。"
	}
	return v
}

// handleServiceGet answers GET /api/system/service.
func (h *API) handleServiceGet(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, h.buildServiceView())
}

// handleServicePost answers POST /api/system/service.
//
// action:
//
//	install / uninstall / start / stop   - performed in this process; the
//	  service control manager rejects them with access denied unless the
//	  client runs elevated, which is reported as 403 need_admin;
//	install-elevated / uninstall-elevated - relaunch this exe through the UAC
//	  prompt so the work happens in an elevated copy, then answer 202: the
//	  caller polls the GET above until the state changes.
func (h *API) handleServicePost(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Action string `json:"action"`
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<10))
	if err := dec.Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, fmt.Errorf("invalid JSON body: %w", err))
		return
	}
	action := strings.ToLower(strings.TrimSpace(body.Action))

	if action == "install-elevated" || action == "uninstall-elevated" {
		flagName := "-service-install"
		if action == "uninstall-elevated" {
			flagName = "-service-uninstall"
		}
		if err := h.relaunchElevated(flagName); err != nil {
			writeErr(w, http.StatusForbidden, err)
			return
		}
		writeJSON(w, http.StatusAccepted, map[string]any{
			"elevated": true,
			"message":  "已请求管理员权限，请在 UAC 提示里选择“是”；完成后本页会自动刷新。",
		})
		return
	}

	if !elevate.IsElevated() && action != "" {
		writeJSON(w, http.StatusForbidden, map[string]any{
			"error":      "安装或卸载服务需要管理员权限：请点“以管理员身份执行”，或在管理员命令行里运行 syan-clash.exe -service-install",
			"need_admin": true,
		})
		return
	}

	var err error
	switch action {
	case "install":
		err = h.app.ServiceInstall()
	case "uninstall":
		err = h.app.ServiceUninstall()
	case "start":
		err = h.app.ServiceStart()
	case "stop":
		err = h.app.ServiceStop()
	default:
		writeErr(w, http.StatusBadRequest, fmt.Errorf("未知操作 %q（可用：install / uninstall / start / stop / install-elevated / uninstall-elevated）", body.Action))
		return
	}
	if err != nil {
		status := http.StatusInternalServerError
		if errors.Is(err, winsvc.ErrExists) || errors.Is(err, winsvc.ErrNotInstalled) {
			// Not a failure of the machine, a failure of the request: the
			// card refreshes from the status that comes back either way.
			status = http.StatusConflict
		}
		writeErr(w, status, err)
		return
	}
	writeJSON(w, http.StatusOK, h.buildServiceView())
}

// relaunchElevated runs one of the -service-* switches in an elevated copy of
// this exe. The copy is windowsgui, runs no window and exits when it is done,
// so nothing flashes on screen.
func (h *API) relaunchElevated(flagName string) error {
	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("找不到本程序路径：%w", err)
	}
	args := []string{flagName, "-config", h.app.ServiceConfigPath()}
	if err := elevate.Elevate(exe, args); err != nil {
		return err
	}
	h.app.Logf("已请求以管理员身份执行 %s", flagName)
	return nil
}

// guardView is the payload of the proxy-guard switch.
type guardView struct {
	Enabled bool `json:"enabled"`
	Running bool `json:"running"`
}

// handleProxyGuardGet answers GET /api/system/proxy-guard.
func (h *API) handleProxyGuardGet(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, guardView{
		Enabled: h.app.ProxyGuardEnabled(),
		Running: h.app.ProxyGuardRunning(),
	})
}

// handleProxyGuardSet answers POST /api/system/proxy-guard.
func (h *API) handleProxyGuardSet(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Enabled bool `json:"enabled"`
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<10))
	if err := dec.Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, fmt.Errorf("invalid JSON body: %w", err))
		return
	}
	if err := h.app.SetProxyGuard(body.Enabled); err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	if body.Enabled {
		h.app.Logf("系统代理守卫已开启")
	} else {
		h.app.Logf("系统代理守卫已关闭：退出时不再有额外的守护进程还原系统代理")
	}
	writeJSON(w, http.StatusOK, guardView{
		Enabled: h.app.ProxyGuardEnabled(),
		Running: h.app.ProxyGuardRunning(),
	})
}
