package control

import (
	"errors"
	"fmt"
	"net/http"
	"testing"

	"vvpn/internal/panel"
)

// panelErrStatus decides what the console tells the user about a panel failure.
// The distinction that matters in practice is 401 versus 502: a 401 sends the
// user to the login card, a 502 sends them chasing a server that is fine. The
// import endpoint used to hardcode 502 for everything, which turned "you are not
// logged in" into "the panel is unreachable".
func TestPanelErrStatus(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want int
	}{
		{
			name: "a missing login is 401",
			err:  &panel.Error{Code: http.StatusUnauthorized, Message: "尚未登录小白账号"},
			want: http.StatusUnauthorized,
		},
		{
			name: "a forbidden token is 401 too",
			err:  &panel.Error{Code: http.StatusForbidden},
			want: http.StatusUnauthorized,
		},
		{
			name: "a panel that answered badly is 502",
			err:  &panel.Error{Code: http.StatusInternalServerError, Message: "server error"},
			want: http.StatusBadGateway,
		},
		{
			name: "empty credentials are 400",
			err:  &panel.InvalidInputError{Msg: "请填写邮箱和密码"},
			want: http.StatusBadRequest,
		},
		{
			name: "a timeout is 504",
			err:  fmt.Errorf("Get \"https://example/api\": context deadline exceeded"),
			want: http.StatusGatewayTimeout,
		},
		{
			name: "anything else is 502",
			err:  errors.New("dial tcp: connection refused"),
			want: http.StatusBadGateway,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := panelErrStatus(tc.err); got != tc.want {
				t.Fatalf("panelErrStatus(%v) = %d, want %d", tc.err, got, tc.want)
			}
		})
	}
}
