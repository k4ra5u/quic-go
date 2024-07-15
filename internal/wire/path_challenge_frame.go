package wire

import (
	"bytes"
	"io"

	"github.com/k4ra5u/quic-go/internal/protocol"
)

// A PathChallengeFrame is a PATH_CHALLENGE frame
/* PATCH */
//强制要求PC帧后面有自定义长度的填充
type PathChallengeFrame struct {
	Data    [8]byte
	Padding []byte
}

func parsePathChallengeFrame(r *bytes.Reader, _ protocol.Version) (*PathChallengeFrame, error) {
	frame := &PathChallengeFrame{}
	if _, err := io.ReadFull(r, frame.Data[:]); err != nil {
		if err == io.ErrUnexpectedEOF {
			return nil, io.EOF
		}
		return nil, err
	}
	return frame, nil
}

/* PATCH */
//Append时可以append一个padding
func (f *PathChallengeFrame) Append(b []byte, _ protocol.Version) ([]byte, error) {
	b = append(b, pathChallengeFrameType)
	b = append(b, f.Data[:]...)
	b = append(b, f.Padding...)
	return b, nil
}

// Length of a written frame
/* PATCH */
//返回整个PC帧的长度
func (f *PathChallengeFrame) Length(_ protocol.Version) protocol.ByteCount {
	return protocol.ByteCount(1 + 8 + len(f.Padding))
}
