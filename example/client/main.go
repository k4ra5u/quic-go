package main

//.\main.exe -insecure https://myserver.xx:56121/demo/tile
import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"io"
	"log"
	"net/http"
	"os"

	"github.com/k4ra5u/quic-go"
	"github.com/k4ra5u/quic-go/http3"
	"github.com/k4ra5u/quic-go/internal/testdata"
	"github.com/k4ra5u/quic-go/qlog"
)

func main() {
	quiet := flag.Bool("q", false, "don't print the data")
	//keyLogFile := flag.String("keylog", "", "key log file")
	keyLogFile := "/home/john/Desktop/key.log"
	insecure := true
	flag.Parse()
	//urls := flag.Args()
	urls := []string{"https://127.0.0.1:58443/"}
	//urls := []string{"https://127.0.0.1:58443/index.html"}

	var keyLog io.Writer
	if len(keyLogFile) > 0 {
		f, err := os.Create(keyLogFile)
		if err != nil {
			log.Fatal(err)
		}
		defer f.Close()
		keyLog = f
	}

	pool, err := x509.SystemCertPool()
	if err != nil {
		log.Fatal(err)
	}
	testdata.AddRootCA(pool)

	roundTripper := &http3.RoundTripper{
		TLSClientConfig: &tls.Config{
			//RootCAs:            pool,
			InsecureSkipVerify: insecure,
			KeyLogWriter:       keyLog,
			//NextProtos:         []string{"quic-echo-example"},
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

	//var wg sync.WaitGroup
	//wg.Add(len(urls))
	for _, addr := range urls {
		log.Printf("GET %s", addr)
		rsp, err := hclient.Get(addr)
		if err != nil {
			log.Fatal(err)
		}
		log.Printf("Got response for %s: %#v", addr, rsp)

		body := &bytes.Buffer{}
		_, err = io.Copy(body, rsp.Body)
		if err != nil {
			log.Fatal(err)
		}
		if *quiet {
			log.Printf("Response Body: %d bytes", body.Len())
		} else {
			log.Printf("Response Body (%d bytes):\n%s", body.Len(), body.Bytes())
		}

	}
}
