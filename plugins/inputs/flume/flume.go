package flume

import (
	"encoding/json"
	"errors"
	"github.com/influxdata/telegraf"
	"github.com/influxdata/telegraf/internal"
	"github.com/influxdata/telegraf/plugins/common/tls"
	"github.com/influxdata/telegraf/plugins/inputs"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
)

type Flume struct {
	URLs []string `toml:"urls"`
	Job  string   `toml:"job"`

	HTTPProxy       string            `toml:"http_proxy"`
	ResponseTimeout internal.Duration `toml:"response_timeout"`
	tls.ClientConfig

	Log telegraf.Logger

	client httpClient
}

func (f *Flume) Description() string {
	return "Gathers metrics from Apache flume."
}

var sampleConfig = `
  ## List of urls to query.
  # urls = ["http://localhost:34545"]

  ## The name of the job
  # job_name = "test_job"

  ## Set http_proxy (telegraf uses the system wide proxy settings if it's is not set)
  # http_proxy = "http://localhost:8888"

  ## Set response_timeout (default 5 seconds)
  # response_timeout = "5s"
`

func (f *Flume) SampleConfig() string {
	return sampleConfig
}

type httpClient interface {
	Do(req *http.Request) (*http.Response, error)
}

// Set the proxy. A configured proxy overwrites the system wide proxy.
func getProxyFunc(httpProxy string) func(*http.Request) (*url.URL, error) {
	if httpProxy == "" {
		return http.ProxyFromEnvironment
	}
	proxyURL, err := url.Parse(httpProxy)
	if err != nil {
		return func(_ *http.Request) (*url.URL, error) {
			return nil, errors.New("bad proxy: " + err.Error())
		}
	}
	return func(r *http.Request) (*url.URL, error) {
		return proxyURL, nil
	}
}

// createHTTPClient creates an http client which will timeout at the specified
// timeout period and can follow redirects if specified
func (f *Flume) createHTTPClient() (*http.Client, error) {
	tlsCfg, err := f.ClientConfig.TLSConfig()
	if err != nil {
		return nil, err
	}

	dialer := &net.Dialer{}

	client := &http.Client{
		Transport: &http.Transport{
			Proxy:             getProxyFunc(f.HTTPProxy),
			DialContext:       dialer.DialContext,
			DisableKeepAlives: true,
			TLSClientConfig:   tlsCfg,
		},
		Timeout: f.ResponseTimeout.Duration,
	}
	return client, nil
}

func (f *Flume) Gather(acc telegraf.Accumulator) error {

	if len(f.URLs) == 0 {
		return nil
	}
	if f.client == nil {
		client, err := f.createHTTPClient()
		if err != nil {
			return err
		}
		f.client = client
	}
	var wg sync.WaitGroup
	for _, u := range f.URLs {
		wg.Add(1)
		go func(urls string) {
			f.gather(acc, urls)
			wg.Done()
		}(u)
	}
	wg.Wait()
	return nil
}

func (f *Flume) gather(acc telegraf.Accumulator, urlStr string) {
	addr, err := url.Parse(urlStr)
	if err != nil {
		acc.AddError(err)
		return
	}

	if addr.Scheme != "http" && addr.Scheme != "https" {
		acc.AddError(errors.New("Only http and https are supported "))
		return
	}

	req, err := http.NewRequest("GET", urlStr, nil)
	if err != nil {
		acc.AddError(err)
		return
	}

	resp, err := f.client.Do(req)
	if err != nil {
		acc.AddError(err)
		return
	}
	var FM FlumeMetrics
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		acc.AddError(err)
		return
	}
	resp.Body.Close()

	err = json.Unmarshal(body, &FM)
	if err != nil {
		acc.AddError(err)
		return
	}
	err = FM.gather(acc, f.Job, addr.Host)
	if err != nil {
		acc.AddError(err)
		return
	}
}

type FlumeMetrics map[string]map[string]string

func (fm *FlumeMetrics) gather(acc telegraf.Accumulator, job, server string) (err error) {
	for k, v := range *fm {
		kl := strings.Split(k, ".")
		if len(kl) < 2 {
			continue
		}
		fType := kl[0]
		fName := strings.Join(kl[1:], ".")
		tags := map[string]string{
			"job":    job,
			"type":   fType,
			"name":   fName,
			"server": server,
		}
		fields := make(map[string]interface{})
		for metricsName, metricsValue := range v {
			parseV, e := parseValue(metricsValue)
			if e != nil {
				continue
			}
			fields[metricsName] = parseV
		}
		acc.AddFields("flume", fields, tags)
	}
	return

}

func parseValue(configV string) (float64, error) {
	if v, e := strconv.ParseFloat(configV, 64); e == nil {
		return v, nil
	}

	v, e := strconv.ParseBool(configV)
	if e != nil {
		return 0, e
	}
	if v {
		return 1, nil
	} else {
		return 0, nil
	}

}
func init() {
	inputs.Add("flume", func() telegraf.Input {
		return &Flume{}
	})
}
