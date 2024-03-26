package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/k4ra5u/quic-go"
)

var keyLog io.Writer
var totalWg int
var finished int

//const startPos = 0
//const endPos = 0

func main() {
	//runtime.GOMAXPROCS(4)

	totalWg = 0

	//go func() { log.Fatal(echoServer()) }()

	//keyLogFile := "C:\\Users\\13298\\Desktop\\key.log"
	keyLogFile := "/home/john/Desktop/cjj_related/key.log"
	//keyLogFile := "/mnt/hgfs/work/key.log"

	if len(keyLogFile) > 0 {
		f, err := os.Create(keyLogFile)
		if err != nil {
			log.Fatal(err)
		}
		defer f.Close()
		keyLog = f
	}

	//args := []string{"alternate.localhost.examp1e.net", "192.168.132.1"}
	//args := []string{"alternate.localhost.examp1e.net", "117.33.164.64"}
	target_file := flag.String("f", "", "input file")
	target_addr := flag.String("i", "", "IP")
	target_port := flag.String("p", "", "PORT")
	start_pos := flag.Int("s", 0, "startPos")
	end_pos := flag.Int("e", 0, "endPos")

	flag.Usage = func() {
		flag.PrintDefaults()
	}

	flag.Parse()
	startPos := *start_pos
	endPos := *end_pos

	finished = startPos - 1

	if *target_file == "" && *target_addr == "" {
		flag.Usage()
		return
	}

	if *target_file == "" {
		targetAddr := *target_addr
		targetPort := *target_port
		targetPort = targetPort // useless now

		// if _, _, err := net.SplitHostPort(targetAddr); err != nil {
		// 	targetAddr = net.JoinHostPort(targetAddr, targetPort)
		// }
		var wg sync.WaitGroup
		wg.Add(1)
		totalWg += 1
		//println(totalWg)
		err := attack(targetAddr, &wg)
		if err != nil {
			log.Fatalf("Error: %#v", err)
		}

	} else {
		Content, ferr := os.ReadFile(*target_file)
		if ferr != nil {
			fmt.Errorf("invalid file : %w", ferr)
			return
		}
		ips := [...]string{}
		ipSlice := ips[:]

		file_contents := bytes.Split(Content, []byte("\n"))
		length := len(file_contents)
		log.Printf("Total %d items\n", length)

		for _, file_content := range file_contents {
			ipSlice = append(ipSlice, string(file_content))
		}
		var wg sync.WaitGroup
		//wg.Add(1)

		for i := 0; i < length; i++ {
			if startPos != 0 {
				if i < startPos {
					continue
				}
			}
			if endPos != 0 {
				if i > endPos {
					break
				}
			}
			thisIP := ipSlice[i]
			if thisIP == "" {
				continue
			}
			//fmt.Println(thisIP)
			targetAddr := thisIP

			try_failed := 1
			var err error

			for j := 0; j < 1; j++ {
				wg.Add(1)
				totalWg += 1
				//println(totalWg)
				err = attack(targetAddr, &wg)
				if err == nil {
					break
				}
				//log.Printf("%s:%s", targetAddr, err.Error())
				try_failed -= 1
			}

			//time.Sleep(time.Millisecond * 1)
		}

		//wg.Wait()
		log.Printf("All workers have finished, exiting the program.")
	}
	//fmt.Println()
	//fmt.Printf("%s\n", resp.Body)
}

func attack(connectAddr string, wg *sync.WaitGroup) (err error) {
	defer func() {
		wg.Done()
		totalWg -= 1
		finished += 1
		if finished%1000 == 0 {
			log.Printf("finished: %d", finished)
		}

	}()
	var wgAttack sync.WaitGroup

	serverName := connectAddr
	test_port := "443"
	targetAddr := net.JoinHostPort(serverName, test_port)
	address := targetAddr
	name, port, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("invalid address %v: %w", address, err)
	}
	ip, err := net.LookupIP(name)
	if err != nil {
		return fmt.Errorf("lookup for %v failed: %w", name, err)
	}
	portInt, err := strconv.Atoi(port)
	if err != nil {
		return fmt.Errorf("invalid port: %w", err)
	}
	udpConn, err := net.ListenPacket("udp", ":0")
	if err != nil {
		return err
	}
	udpAddr := &net.UDPAddr{
		IP:   ip[0],
		Port: portInt,
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond*500)

	session, err := quic.Dial(ctx, udpConn, udpAddr,
		&tls.Config{
			//NextProtos: []string{"hq-interop"},
			NextProtos:         []string{"h3", "h3-29", "h3-34", "h3-27", "http/0.9", "hq", "hq-29", "doq", "dns", "spdy", "http/1.1", "http/2", "ftp", "imap", "smtp", "pop3", "quic", "h3-q050", "h3-23"},
			ServerName:         serverName,
			InsecureSkipVerify: true,
			KeyLogWriter:       keyLog,
		},
		&quic.Config{
			Versions:           []quic.VersionNumber{quic.Version1},
			MaxIncomingStreams: -1,
		})
	if err != nil {
		log.Printf(strconv.Itoa(finished), err.Error())
		udpConn.Close()
		cancel()
	} else {
		targetAlpn := session.ConnectionState().TLS.NegotiatedProtocol
		targetPort := test_port
		session.CloseWithError(0, "")
		udpConn.Close()
		cancel()
		if targetAddr != "" {

			fmt.Printf("%s %s %s\n", connectAddr, targetPort, targetAlpn)
			return nil
		}
	}

	maybePorts := []string{"4443", "8443", "3443", "2083", "80", "444", "9443", "853", "7081"}
	for _, test_Port := range maybePorts {
		wgAttack.Add(1)
		go func(pretargetPort string) {
			defer func() {
				wgAttack.Done()
			}()
			targetAddr := net.JoinHostPort(serverName, pretargetPort)
			//println(serverName)
			address := targetAddr
			name, port, err := net.SplitHostPort(address)
			if err != nil {
				return
				//return "", "", fmt.Errorf("invalid address %v: %w", address, err)
			}
			ip, err := net.LookupIP(name)
			if err != nil {
				return
				//return "", "", fmt.Errorf("lookup for %v failed: %w", name, err)
			}
			portInt, err := strconv.Atoi(port)
			if err != nil {
				return
				//return "", "", fmt.Errorf("invalid port: %w", err)
			}
			udpConn, err := net.ListenPacket("udp", ":0")
			if err != nil {
				return
				//return "", "", err
			}
			//defer func() { _ = udpConn.Close() }()
			udpAddr := &net.UDPAddr{
				IP:   ip[0],
				Port: portInt,
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond*500)

			session, err := quic.Dial(ctx, udpConn, udpAddr,
				&tls.Config{
					//NextProtos: []string{"hq-interop"},
					NextProtos:         []string{"h3", "h3-29", "h3-34", "h3-27", "http/0.9", "hq", "hq-29", "doq", "dns", "spdy", "http/1.1", "http/2", "ftp", "imap", "smtp", "pop3", "quic", "h3-q050", "h3-23"},
					ServerName:         serverName,
					InsecureSkipVerify: true,
					KeyLogWriter:       keyLog,
				},
				&quic.Config{
					Versions:           []quic.VersionNumber{quic.Version1},
					MaxIncomingStreams: -1,
				})
			if err != nil {
				//session.CloseWithError(0, "")
				//log.Fatal(err)
				udpConn.Close()
				cancel()
				//continue
			} else {
				targetAlpn := session.ConnectionState().TLS.NegotiatedProtocol
				session.CloseWithError(0, "")
				udpConn.Close()
				cancel()
				//fmt.Println("Negotiated ALPN:", targetAlpn)
				if targetAddr != "" {
					targetPort := pretargetPort
					fmt.Printf("%s %s %s\n", connectAddr, targetPort, targetAlpn)
					return
					//return targetPort, targetAlpn, nil
				}
			}
		}(test_Port)
	}
	wgAttack.Wait()
	return err

	/*



		udpAddr := &net.UDPAddr{
			IP:   ip[0],
			Port: portInt,
		}

		session, err := quic.Dial(ctx, udpConn, udpAddr,
			&tls.Config{
				//NextProtos: []string{"hq-interop"},
				//NextProtos:         []string{targetAlpn},
				ServerName:         serverName,
				InsecureSkipVerify: true,
				KeyLogWriter:       keyLog,
			},
			&quic.Config{
				Versions:           []quic.VersionNumber{quic.Version1},
				MaxIncomingStreams: -1,
			})

		if err != nil {
			//log.Printf("%s:%s", connectAddr, err.Error())
			return false, err
		}

		defer func() { _ = session.CloseWithError(0, "") }()

		if err := setupSession(session); err != nil {
			//log.Printf("ggggg%s", err.Error())
			return nil, err
		}
	*/

}
