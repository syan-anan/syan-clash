package control

import (
	"context"
	"net"
	"net/http"
	"time"

	"vvpn/internal/app"
)

// Server is the running control-plane HTTP server.
type Server struct {
	http *http.Server
	ln   net.Listener
}

// Addr is the address the server is listening on.
func (s *Server) Addr() net.Addr { return s.ln.Addr() }

// Shutdown stops the server, waiting briefly for in-flight requests.
func (s *Server) Shutdown(ctx context.Context) error { return s.http.Shutdown(ctx) }

// Serve starts the control API on an existing listener and does not block.
//
// Taking a listener lets the caller bind the port first (so it knows the real
// address even when port 0 was requested) and lets a bind failure be reported
// before anything else starts.
func Serve(ln net.Listener, a *app.App) (*Server, error) {
	handler := New(a).Handler()
	srv := &Server{
		ln: ln,
		http: &http.Server{
			Handler:           handler,
			ReadHeaderTimeout: 10 * time.Second,
		},
	}
	go func() {
		_ = srv.http.Serve(ln)
	}()
	return srv, nil
}
