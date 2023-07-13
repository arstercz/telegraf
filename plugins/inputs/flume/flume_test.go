package flume

import (
	"github.com/influxdata/telegraf/testutil"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

func TestGather(t *testing.T) {
	f := &Flume{
		URLs: []string{},
		Job:  "test_job",
	}
	server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		rw.Write([]byte(`{"SINK.s1": {"ConnectionCreatedCount": "100", "StartTime": "1689061980684"}}`))
	}))
	defer server.Close()

	f.client = server.Client()
	f.URLs = []string{server.URL}

	acc := &testutil.Accumulator{}

	err := f.Gather(acc)

	if err != nil {
		t.Errorf("unexpected error: %s", err)
	}

	expectedFields := map[string]interface{}{
		"ConnectionCreatedCount": float64(100),
		"StartTime":              float64(1689061980684),
	}
	if err != nil {
		t.Errorf("url.Parse error: %s", err)
	}
	addr, err := url.Parse(server.URL)
	if err != nil {
		t.Errorf("url.Parse error: %s", err)
	}
	expectedTags := map[string]string{
		"job":    "test_job",
		"type":   "SINK",
		"name":   "s1",
		"server": addr.Host,
	}

	acc.AssertContainsTaggedFields(t, "flume", expectedFields, expectedTags)
}
