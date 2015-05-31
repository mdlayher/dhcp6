package dhcp6

import (
	"errors"
)

var (
	// errInvalidTransactionID is returned when a transaction ID not exactly
	// 3 bytes in length.
	errInvalidTransactionID = errors.New("transaction ID must be exactly 3 bytes")
)

// Packet represents a raw DHCPv6 packet, using the format described in IETF
// RFC 3315, Section 6.  A Packet has methods which allow easy access to
// its message type, transaction ID, and any options available in the Packet.
//
// The Packet type is typically only needed for low-level operations within the
// server, or in tests.
type Packet []byte

// MessageType returns the MessageType constant identified in this Packet.
func (p Packet) MessageType() MessageType {
	// Empty Packet means no message type
	if len(p) == 0 {
		return 0
	}

	return MessageType(p[0])
}

// TransactionID returns the transaction ID byte slice identified in this
// Packet.
func (p Packet) TransactionID() []byte {
	// If Packet is too short to contain a transaction ID,
	// just return a nil ID
	if len(p) < 4 {
		return nil
	}

	return p[1:4]
}

// option represents an individual DHCP Option, as defined in IETF RFC 3315,
// Section 22.  An Option carries both an OptionCode and its raw Data.  The
// format of option data varies depending on the option code.
type option struct {
	Code OptionCode
	Data []byte
}

// Options parses a Packet's options and returns them as an Options map.
func (p Packet) Options() Options {
	// Skip message type and transaction ID
	return parseOptions(p[4:])
}

// NewPacket creates a new Packet from an input message type, transaction ID,
// and Options map.  The resulting Packet can be used to send a request to
// a DHCP server, or a response to DHCP client.
//
// The transaction ID must be exactly 3 bytes, or an error will be returned.
//
// The Packet type is typically only needed for low-level operations within the
// server, or in tests.
func NewPacket(mt MessageType, txID []byte, options Options) (Packet, error) {
	// Transaction ID must always be 3 bytes
	if len(txID) != 3 {
		return nil, errInvalidTransactionID
	}

	// If no options, allocate only enough space for message type
	// and transaction ID
	if len(options) == 0 {
		p := make(Packet, 4)
		p[0] = byte(mt)
		copy(p[1:4], txID[:])
		return p, nil
	}

	// Calculate size of Packet so the entire Packet can be allocated
	// at once

	// 1 byte: message type
	// 3 bytes: transaction ID
	// N bytes: options slice byte count
	opts := options.enumerate()
	i := 4 + opts.count()

	// Allocate Packet and fill basic fields
	p := make(Packet, i, i)
	p[0] = byte(mt)
	copy(p[1:4], txID[:])

	// Write options into Packet at proper index
	opts.write(p[4:])

	return p, nil
}
