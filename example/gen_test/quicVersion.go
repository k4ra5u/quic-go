package main

import (
	"fmt"
	"net"
	"sync"
)

type quicVersion struct {
	BaseArgs
}

func (quicVersion *quicVersion) Attack() (response *HTTPMessage, err error) {
	var wgAttack sync.WaitGroup
	serverHost := quicVersion.targetHost
	firstTestPort := "443"
	targetAddr := net.JoinHostPort(serverHost, firstTestPort)
	quicVersion.targetAddr = targetAddr
	session, cancel, err := quicVersion.Make_one_session()
	defer func() {
		_ = session.CloseWithError(0, "")
		cancel()
	}()
	if err != nil {
		//log.Printf(err.Error())
	} else {
		targetAlpn := session.ConnectionState().TLS.NegotiatedProtocol
		session.CloseWithError(0, "")
		if targetAddr != "" {

			fmt.Printf("%s %s %s\n", serverHost, firstTestPort, targetAlpn)
			return nil, nil
		}
	}

	maybePorts := []string{"4443", "8443", "3443", "2083", "80", "444", "9443", "853", "7081"}
	for _, test_Port := range maybePorts {
		wgAttack.Add(1)
		go func(pretargetPort string) {
			defer func() {
				wgAttack.Done()
			}()
			targetAddr := net.JoinHostPort(serverHost, pretargetPort)
			quicVersion.targetAddr = targetAddr
			session, cancel, err := quicVersion.Make_one_session()
			defer func() {
				_ = session.CloseWithError(0, "")
				cancel()
			}()
			if err != nil {
				//log.Printf(err.Error())
			} else {
				targetAlpn := session.ConnectionState().TLS.NegotiatedProtocol
				session.CloseWithError(0, "")
				//fmt.Println("Negotiated ALPN:", targetAlpn)
				if targetAddr != "" {
					fmt.Printf("%s %s %s\n", serverHost, pretargetPort, targetAlpn)
					return
				}
			}
		}(test_Port)
	}
	wgAttack.Wait()

	return nil, nil
}
