package quic

import (
	"fmt"

	"github.com/iafoosball/quic-go/internal/protocol"
	"github.com/iafoosball/quic-go/internal/wire"
)

type RetransmissionQueue struct {
	initial           []wire.Frame
	initialCryptoData []*wire.CryptoFrame

	handshake           []wire.Frame
	handshakeCryptoData []*wire.CryptoFrame

	appData []wire.Frame

	version protocol.VersionNumber
}

func NewRetransmissionQueue(ver protocol.VersionNumber) *RetransmissionQueue {
	return &RetransmissionQueue{version: ver}
}

func (q *RetransmissionQueue) AddInitial(f wire.Frame) {
	if cf, ok := f.(*wire.CryptoFrame); ok {
		q.initialCryptoData = append(q.initialCryptoData, cf)
		return
	}
	q.initial = append(q.initial, f)
}

func (q *RetransmissionQueue) AddHandshake(f wire.Frame) {
	if cf, ok := f.(*wire.CryptoFrame); ok {
		q.handshakeCryptoData = append(q.handshakeCryptoData, cf)
		return
	}
	q.handshake = append(q.handshake, f)
}

func (q *RetransmissionQueue) HasInitialData() bool {
	return len(q.initialCryptoData) > 0 || len(q.initial) > 0
}

func (q *RetransmissionQueue) HasHandshakeData() bool {
	return len(q.handshakeCryptoData) > 0 || len(q.handshake) > 0
}

func (q *RetransmissionQueue) HasAppData() bool {
	return len(q.appData) > 0
}

func (q *RetransmissionQueue) AddAppData(f wire.Frame) {
	if _, ok := f.(*wire.StreamFrame); ok {
		panic("STREAM frames are handled with their respective streams.")
	}
	q.appData = append(q.appData, f)
}

func (q *RetransmissionQueue) GetInitialFrame(maxLen protocol.ByteCount) wire.Frame {
	if len(q.initialCryptoData) > 0 {
		f := q.initialCryptoData[0]
		newFrame, needsSplit := f.MaybeSplitOffFrame(maxLen, q.version)
		if newFrame == nil && !needsSplit { // the whole frame fits
			q.initialCryptoData = q.initialCryptoData[1:]
			return f
		}
		if newFrame != nil { // frame was split. Leave the original frame in the queue.
			return newFrame
		}
	}
	if len(q.initial) == 0 {
		return nil
	}
	f := q.initial[0]
	if f.Length(q.version) > maxLen {
		return nil
	}
	q.initial = q.initial[1:]
	return f
}

func (q *RetransmissionQueue) GetHandshakeFrame(maxLen protocol.ByteCount) wire.Frame {
	if len(q.handshakeCryptoData) > 0 {
		f := q.handshakeCryptoData[0]
		newFrame, needsSplit := f.MaybeSplitOffFrame(maxLen, q.version)
		if newFrame == nil && !needsSplit { // the whole frame fits
			q.handshakeCryptoData = q.handshakeCryptoData[1:]
			return f
		}
		if newFrame != nil { // frame was split. Leave the original frame in the queue.
			return newFrame
		}
	}
	if len(q.handshake) == 0 {
		return nil
	}
	f := q.handshake[0]
	if f.Length(q.version) > maxLen {
		return nil
	}
	q.handshake = q.handshake[1:]
	return f
}

func (q *RetransmissionQueue) GetAppDataFrame(maxLen protocol.ByteCount) wire.Frame {
	if len(q.appData) == 0 {
		return nil
	}
	f := q.appData[0]
	if f.Length(q.version) > maxLen {
		return nil
	}
	q.appData = q.appData[1:]
	return f
}

func (q *RetransmissionQueue) DropPackets(encLevel protocol.EncryptionLevel) {
	//nolint:exhaustive // Can only drop Initial and Handshake packet number space.
	switch encLevel {
	case protocol.EncryptionInitial:
		q.initial = nil
		q.initialCryptoData = nil
	case protocol.EncryptionHandshake:
		q.handshake = nil
		q.handshakeCryptoData = nil
	default:
		panic(fmt.Sprintf("unexpected encryption level: %s", encLevel))
	}
}
