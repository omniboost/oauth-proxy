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
	"github.com/pkg/errors"
)

var (
	GRAFANA_LOKI_URL   = os.Getenv("GRAFANA_LOKI_URL")
	GRAFANA_LOKI_USER  = os.Getenv("GRAFANA_LOKI_USER")
	GRAFANA_LOKI_TOKEN = os.Getenv("GRAFANA_LOKI_TOKEN")
)

func PushRequestResponseToGrafana(r *http.Request, w http.ResponseWriter, metrics httpsnoop.Metrics) error {
	if GRAFANA_LOKI_URL == "" {
		return nil
	}

	// create data to send
	logLevel := "info"
	if metrics.Code >= 400 {
		logLevel = "error"
	}
	push := &logproto.PushRequest{
		Streams: []logproto.Stream{
			{
				Labels: `{service="oauth-proxy"}`,
				Entries: []logproto.Entry{
					{
						Timestamp: time.Now(),
						Line:      r.URL.Path,
						StructuredMetadata: []logproto.LabelAdapter{
							{
								Name:  "level",
								Value: logLevel,
							},
							{
								Name:  "path",
								Value: r.URL.Path,
							},
							{
								Name:  "status_code",
								Value: strconv.Itoa(metrics.Code),
							},
							{
								Name:  "duration",
								Value: strconv.FormatFloat(float64(metrics.Duration.Microseconds())/1000.0, 'f', -1, 64) + "ms",
							},
						},
					},
				},
			},
		},
	}

	// convert data to protobuf
	buf, err := proto.Marshal(push)
	if err != nil {
		return errors.WithStack(err)
	}

	// convert protobuf to snappy
	buf = snappy.Encode(nil, buf)

	// create actual http request to grafana
	grafanaReq, err := http.NewRequest("POST", GRAFANA_LOKI_URL, bytes.NewBuffer(buf))
	grafanaReq.SetBasicAuth(GRAFANA_LOKI_USER, GRAFANA_LOKI_TOKEN)
	grafanaReq.Header.Set("Content-Type", "application/x-protobuf")
	client := http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			TLSHandshakeTimeout:   5 * time.Second,
			ResponseHeaderTimeout: 5 * time.Second,
		},
	}

	// make request
	grafanaResp, err := client.Do(grafanaReq)
	if err != nil {
		return errors.WithStack(err)
	}
	return grafanaResp.Body.Close()
}

func logToGrafana(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		func() {
			metrics := httpsnoop.CaptureMetrics(h, w, r)
			err := PushRequestResponseToGrafana(r, w, metrics)
			if err != nil {
				logrus.Debug("PushRequestResponseToGrafana error: ", err)
			}
		}()
	})
}
