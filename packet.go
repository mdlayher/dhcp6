package dhcp6

import (
	"errors"
)

var (
	// errInvalidPacket is returned when a byte slice does not contain enough
	// data to create a valid Packet.  A Packet must have at least a message type
	// and transaction ID.
	errInvalidPacket = errors.New("not enough bytes for valid packet")
)

// Packet represents a raw DHCPv6 packet, using the format described in RFC 3315,
// Section 6.
//
// The Packet type is typically only needed for low-level operations within the
// client, server, or in tests.
type Packet struct {
	// MessageType specifies the DHCP message type constant, such as
	// MessageTypeSolicit, MessageTypeAdvertise, etc.
	MessageType MessageType

	// TransactionID specifies the DHCP transaction ID.  The transaction ID must
	// be the same for all message exchanges in one DHCP transaction.
	TransactionID [3]byte

	// Options specifies a map of DHCP options.  Its methods can be used to
	// retrieve data from an incoming packet, or send data with an outgoing
	// packet.
	Options Options
}

// Bytes implements Byteser, and allocates a byte slice containing the data
// from a Packet.
func (p *Packet) Bytes() []byte {
	// 1 byte: message type
	// 3 bytes: transaction ID
	// N bytes: options slice byte count
	opts := p.Options.enumerate()
	b := make([]byte, 4+opts.count())

	b[0] = byte(p.MessageType)
	copy(b[1:4], p.TransactionID[:])
	opts.write(b[4:])

	return b
}

// parsePacket parses a raw byte slice into a Packet.  If the byte slice
// does not contain enough data to form a valid Packet, errInvalidPacket
// is returned.
func parsePacket(b []byte) (*Packet, error) {
	// Packet must contain at least a message type and transaction ID
	if len(b) < 4 {
		return nil, errInvalidPacket
	}

	txID := [3]byte{}
	copy(txID[:], b[1:4])

	return &Packet{
		MessageType:   MessageType(b[0]),
		TransactionID: txID,
		Options:       parseOptions(b[4:]),
	}, nil
}
