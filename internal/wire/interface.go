package wire

import (
	"github.com/k4ra5u/quic-go/internal/protocol"
)

// A Frame in QUIC
type Frame interface {
	Append(b []byte, version protocol.Version) ([]byte, error)
	Length(version protocol.Version) protocol.ByteCount
}
