package oauthproxy

import (
	"bytes"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/felixge/httpsnoop"
	proto "github.com/gogo/protobuf/proto"
	"github.com/golang/snappy"
	"github.com/grafana/loki/v3/pkg/logproto"
	"github.com/lytics/logrus"
	"github.com/omniboost/oauth-proxy/mysql"
	"github.com/pkg/errors"
)

var (
	GRAFANA_LOKI_URL   = os.Getenv("GRAFANA_LOKI_URL")
	GRAFANA_LOKI_USER  = os.Getenv("GRAFANA_LOKI_USER")
	GRAFANA_LOKI_TOKEN = os.Getenv("GRAFANA_LOKI_TOKEN")
)

// grafanaEvent is a single log entry for the loki stream identified by labels
type grafanaEvent struct {
	labels string
	entry  logproto.Entry
}

// GrafanaEvents holds events for one token request. The token worker finishes
// writing before returning its result; the handler then adds its request log
// and sends the batch. A buffer must not be shared between requests.
type GrafanaEvents struct {
	events []grafanaEvent
	limit  int
}

// grafanaMaxEventsPerRequest is a safety net: a token request normally queues
// at most a token saved event and its request log
const grafanaMaxEventsPerRequest = 100

func NewGrafanaEvents() *GrafanaEvents {
	return &GrafanaEvents{limit: grafanaMaxEventsPerRequest}
}

// queue never blocks on network I/O, including while a DB transaction is held.
func (events *GrafanaEvents) queue(labels string, entry logproto.Entry) {
	if events == nil || GRAFANA_LOKI_URL == "" {
		return
	}
	if len(events.events) >= events.limit {
		logrus.Debug("grafana request buffer full; dropping event")
		return
	}
	events.events = append(events.events, grafanaEvent{labels: labels, entry: entry})
}

// QueueRequestLog queues a log entry for a handled HTTP request
func (events *GrafanaEvents) QueueRequestLog(r *http.Request, metrics httpsnoop.Metrics) {
	logLevel := "info"
	if metrics.Code >= 400 {
		logLevel = "error"
	}

	events.queue(`{service="oauth-proxy"}`, logproto.Entry{
		Timestamp: time.Now(),
		Line:      r.URL.Path,
		StructuredMetadata: []logproto.LabelAdapter{
			{Name: "level", Value: logLevel},
			{Name: "path", Value: r.URL.Path},
			{Name: "status_code", Value: strconv.Itoa(metrics.Code)},
			{Name: "duration", Value: strconv.FormatFloat(float64(metrics.Duration.Microseconds())/1000.0, 'f', -1, 64) + "ms"},
		},
	})
}

// Stream labels for secret reads and writes, used to count how often secrets
// are read and written (IN-5149). Token values are never logged.
const (
	grafanaSecretReadLabels  = `{service="oauth-proxy", event="secret", operation="read"}`
	grafanaSecretWriteLabels = `{service="oauth-proxy", event="secret", operation="write"}`
)

// QueueSecretRead queues an event when a token row is looked up in the
// database, whether it's found or not. The lookup while saving a token is part
// of the write and isn't counted.
func (events *GrafanaEvents) QueueSecretRead(app, grantType string) {
	events.queue(grafanaSecretReadLabels, logproto.Entry{
		Timestamp: time.Now(),
		Line:      "secret read for app " + app,
		StructuredMetadata: []logproto.LabelAdapter{
			{Name: "level", Value: "info"},
			{Name: "app", Value: app},
			{Name: "grant_type", Value: grantType},
		},
	})
}

// QueueSecretSaved queues an event when a new refresh token and/or access
// token is written to the database, also when saving failed. Changes to only
// e.g. the expiry don't count as a write.
func (events *GrafanaEvents) QueueSecretSaved(dbToken mysql.OauthToken, refreshTokenChanged, accessTokenChanged bool) {
	if !refreshTokenChanged && !accessTokenChanged {
		return
	}

	events.queue(grafanaSecretWriteLabels, logproto.Entry{
		Timestamp: time.Now(),
		Line:      "secret saved for app " + dbToken.App,
		StructuredMetadata: []logproto.LabelAdapter{
			{Name: "level", Value: "info"},
			{Name: "app", Value: dbToken.App},
			{Name: "grant_type", Value: dbToken.GrantType},
			{Name: "refresh_token_changed", Value: strconv.FormatBool(refreshTokenChanged)},
			{Name: "access_token_changed", Value: strconv.FormatBool(accessTokenChanged)},
		},
	})
}

// QueueSecretRevoked queues one event per revoke that marks a token as revoked
// in the database, also when that failed.
func (events *GrafanaEvents) QueueSecretRevoked(app, grantType string) {
	events.queue(grafanaSecretWriteLabels, logproto.Entry{
		Timestamp: time.Now(),
		Line:      "secret revoked for app " + app,
		StructuredMetadata: []logproto.LabelAdapter{
			{Name: "level", Value: "info"},
			{Name: "app", Value: app},
			{Name: "grant_type", Value: grantType},
		},
	})
}

// PushEventsToGrafana consumes and sends this request's events in a single push.
func (s *Server) PushEventsToGrafana(events *GrafanaEvents) error {
	if events == nil || GRAFANA_LOKI_URL == "" {
		return nil
	}

	batch := events.events
	events.events = nil
	if len(batch) == 0 {
		return nil
	}

	// group entries per stream, keeping the order in which they were queued
	push := &logproto.PushRequest{}
	streams := map[string]int{}
	for _, e := range batch {
		i, ok := streams[e.labels]
		if !ok {
			i = len(push.Streams)
			streams[e.labels] = i
			push.Streams = append(push.Streams, logproto.Stream{Labels: e.labels})
		}
		push.Streams[i].Entries = append(push.Streams[i].Entries, e.entry)
	}

	return pushToGrafana(s.client, push)
}

func pushToGrafana(client *http.Client, push *logproto.PushRequest) error {
	// convert data to protobuf
	buf, err := proto.Marshal(push)
	if err != nil {
		return errors.WithStack(err)
	}

	// convert protobuf to snappy
	buf = snappy.Encode(nil, buf)

	// create actual http request to grafana
	grafanaReq, err := http.NewRequest("POST", GRAFANA_LOKI_URL, bytes.NewBuffer(buf))
	if err != nil {
		return errors.WithStack(err)
	}

	grafanaReq.SetBasicAuth(GRAFANA_LOKI_USER, GRAFANA_LOKI_TOKEN)
	grafanaReq.Header.Set("Content-Type", "application/x-protobuf")

	// make request
	grafanaResp, err := client.Do(grafanaReq)
	if err != nil {
		return errors.WithStack(err)
	}
	return grafanaResp.Body.Close()
}

// logToGrafana owns the buffer and passes it explicitly to the token handler.
func (s *Server) logToGrafana(h func(http.ResponseWriter, *http.Request, *GrafanaEvents)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		events := NewGrafanaEvents()
		metrics := httpsnoop.CaptureMetrics(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			h(w, r, events)
		}), w, r)
		events.QueueRequestLog(r, metrics)
		if err := s.PushEventsToGrafana(events); err != nil {
			logrus.Debug("PushEventsToGrafana error: ", err)
		}
	}
}
