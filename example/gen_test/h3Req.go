package main

import (
	"bytes"
	"crypto/tls"
	"io"
	"log"
	"net/http"
	"time"

	"github.com/k4ra5u/quic-go"
	"github.com/k4ra5u/quic-go/http3"
	"github.com/k4ra5u/quic-go/qlog"
)

type h3Req struct {
	BaseArgs
}

func (h3Req *h3Req) Attack() (response *HTTPMessage, err error) {
	repeatTimes := h3Req.repeatTimes
	url := h3Req.targetAddr
	quiet := h3Req.quiet

	if url[0] != 'h' {
		url = "https://" + url
	}
	for i := 0; uint64(i) < repeatTimes; i++ {
		roundTripper := &http3.RoundTripper{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
				KeyLogWriter:       keyLog,
			},
			QuicConfig: &quic.Config{
				Versions: []quic.VersionNumber{quic.Version1},
				Tracer:   qlog.DefaultTracer,
			},
		}
		defer roundTripper.Close()
		hclient := &http.Client{
			Transport: roundTripper,
		}
		startTime := time.Now()
		rsp, err := hclient.Get(url)
		if err != nil {
			log.Println(err)
			continue
		}
		endTime := time.Now()
		duration := endTime.Sub(startTime)
		log.Println("GET", url, "time:", duration.Milliseconds(), "ms", "status:", rsp.StatusCode)

		body := &bytes.Buffer{}
		_, err = io.Copy(body, rsp.Body)
		if err != nil {
			log.Println(err)
			continue
		}
		if !quiet {
			log.Printf("GET %s", url)
			log.Printf("Response Status: %d, %d bytes", rsp.StatusCode, body.Len())
			log.Printf("Got response for %s: %#v", url, rsp)
			log.Printf("Response Body (%d bytes):\n%s", body.Len(), body.Bytes())
		}
		time.Sleep(time.Second * 1)

	}

	return nil, nil
}
