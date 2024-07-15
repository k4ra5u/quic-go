package quic

import (
	"fmt"

	"github.com/k4ra5u/quic-go/internal/protocol"
	"github.com/k4ra5u/quic-go/internal/qerr"
	"github.com/k4ra5u/quic-go/internal/wire"
)

type connIDGenerator struct {
	generator  ConnectionIDGenerator
	highestSeq uint64

	activeSrcConnIDs        map[uint64]protocol.ConnectionID
	initialClientDestConnID *protocol.ConnectionID // nil for the client

	addConnectionID        func(protocol.ConnectionID)
	getStatelessResetToken func(protocol.ConnectionID) protocol.StatelessResetToken
	removeConnectionID     func(protocol.ConnectionID)
	retireConnectionID     func(protocol.ConnectionID)
	replaceWithClosed      func([]protocol.ConnectionID, []byte)
	queueControlFrame      func(wire.Frame)
}

func newConnIDGenerator(
	initialConnectionID protocol.ConnectionID,
	initialClientDestConnID *protocol.ConnectionID, // nil for the client
	addConnectionID func(protocol.ConnectionID),
	getStatelessResetToken func(protocol.ConnectionID) protocol.StatelessResetToken,
	removeConnectionID func(protocol.ConnectionID),
	retireConnectionID func(protocol.ConnectionID),
	replaceWithClosed func([]protocol.ConnectionID, []byte),
	queueControlFrame func(wire.Frame),
	generator ConnectionIDGenerator,
) *connIDGenerator {
	m := &connIDGenerator{
		generator:              generator,
		activeSrcConnIDs:       make(map[uint64]protocol.ConnectionID),
		addConnectionID:        addConnectionID,
		getStatelessResetToken: getStatelessResetToken,
		removeConnectionID:     removeConnectionID,
		retireConnectionID:     retireConnectionID,
		replaceWithClosed:      replaceWithClosed,
		queueControlFrame:      queueControlFrame,
	}
	m.activeSrcConnIDs[0] = initialConnectionID
	m.initialClientDestConnID = initialClientDestConnID
	return m
}

func (m *connIDGenerator) SetMaxActiveConnIDs(limit uint64) error {
	if m.generator.ConnectionIDLen() == 0 {
		return nil
	}
	// The active_connection_id_limit transport parameter is the number of
	// connection IDs the peer will store. This limit includes the connection ID
	// used during the handshake, and the one sent in the preferred_address
	// transport parameter.
	// We currently don't send the preferred_address transport parameter,
	// so we can issue (limit - 1) connection IDs.
	for i := uint64(len(m.activeSrcConnIDs)); i < min(limit, protocol.MaxIssuedConnectionIDs); i++ {
		if err := m.issueNewConnID(0); err != nil {
			return err
		}
	}
	return nil
}

func (m *connIDGenerator) Retire(seq uint64, sentWithDestConnID protocol.ConnectionID) error {
	if seq > m.highestSeq {
		return &qerr.TransportError{
			ErrorCode:    qerr.ProtocolViolation,
			ErrorMessage: fmt.Sprintf("retired connection ID %d (highest issued: %d)", seq, m.highestSeq),
		}
	}
	connID, ok := m.activeSrcConnIDs[seq]
	// We might already have deleted this connection ID, if this is a duplicate frame.
	if !ok {
		return nil
	}
	if connID == sentWithDestConnID {
		return &qerr.TransportError{
			ErrorCode:    qerr.ProtocolViolation,
			ErrorMessage: fmt.Sprintf("retired connection ID %d (%s), which was used as the Destination Connection ID on this packet", seq, connID),
		}
	}
	m.retireConnectionID(connID)
	delete(m.activeSrcConnIDs, seq)
	// Don't issue a replacement for the initial connection ID.
	if seq == 0 {
		return nil
	}
	/* PATCH */
	//原有的逻辑是如果收到RetireConn，就立刻发送一个新的NewCid，改成如果activeSrcConnIDs清空了，就发送一个新的Newcid
	//return m.issueNewConnID(0)
	if len(m.activeSrcConnIDs) == 0 {
		return m.issueNewConnID(0)
	}
	return nil
}

/* PATCH */
// 修改issueNewConnID逻辑，增加一个参数可以传递RetirePriorTo
// 修改highestSeq自增的顺序，以防CID发出去了，但是highestSeq还没有自增
func (m *connIDGenerator) issueNewConnID(RetireID uint64) error {
	m.highestSeq++
	connID, err := m.generator.GenerateConnectionID()
	if err != nil {
		return err
	}
	m.activeSrcConnIDs[m.highestSeq] = connID
	m.addConnectionID(connID)
	m.queueControlFrame(&wire.NewConnectionIDFrame{
		SequenceNumber:      m.highestSeq,
		ConnectionID:        connID,
		RetirePriorTo:       RetireID,
		StatelessResetToken: m.getStatelessResetToken(connID),
	})

	return nil
}

func (m *connIDGenerator) SetHandshakeComplete() {
	if m.initialClientDestConnID != nil {
		m.retireConnectionID(*m.initialClientDestConnID)
		m.initialClientDestConnID = nil
	}
}

func (m *connIDGenerator) RemoveAll() {
	if m.initialClientDestConnID != nil {
		m.removeConnectionID(*m.initialClientDestConnID)
	}
	for _, connID := range m.activeSrcConnIDs {
		m.removeConnectionID(connID)
	}
}

func (m *connIDGenerator) ReplaceWithClosed(connClose []byte) {
	connIDs := make([]protocol.ConnectionID, 0, len(m.activeSrcConnIDs)+1)
	if m.initialClientDestConnID != nil {
		connIDs = append(connIDs, *m.initialClientDestConnID)
	}
	for _, connID := range m.activeSrcConnIDs {
		connIDs = append(connIDs, connID)
	}
	m.replaceWithClosed(connIDs, connClose)
}

/* PATCH */
//添加一个获取当前最高的seq的函数
func (m *connIDGenerator) GetHighestSeq() uint64 {
	return m.highestSeq
}

// 添加一个可以增加CID的函数，这样就不用自己生成CID了
func (m *connIDGenerator) AddCID(seqID uint64) error {
	return m.issueNewConnID(seqID)
}
