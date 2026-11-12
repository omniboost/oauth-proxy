package oauthproxy

import (
	"strconv"
	"time"

	"github.com/getsentry/sentry-go"
)

// captureException sends err to sentry. On Lambda the execution environment
// is frozen after the response is returned, so the event is flushed right
// away instead of when the process exits.
func captureException(hub *sentry.Hub, err error) {
	hub.CaptureException(err)
	hub.Flush(2 * time.Second)
}

// setSentryTokenID tags the request's sentry events with the database id of
// the token, so errors can be traced to a row without sending secrets
func setSentryTokenID(hub *sentry.Hub, id int) {
	if hub == nil || id == 0 {
		return
	}
	hub.ConfigureScope(func(scope *sentry.Scope) {
		scope.SetTag("TokenID", strconv.Itoa(id))
	})
}
