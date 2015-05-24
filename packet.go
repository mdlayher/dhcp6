package dhcp6

import (
	"encoding/binary"
	"errors"
)

var (
	// errInvalidTransactionID is returned when a transaction ID not exactly
	// 3 bytes in length.
	errInvalidTransactionID = errors.New("transaction ID must be exactly 3 bytes")
)

// packet represents a raw DHCPv6 packet, using the format described in IETF
// RFC 3315, Section 6.  A packet has methods which allow easy access to
// its message type, transaction ID, and any options available in the packet.
type packet []byte

// MessageType returns the MessageType constant identified in this packet.
func (p packet) MessageType() MessageType {
	// Empty packet means no message type
	if len(p) == 0 {
		return 0
	}

	return MessageType(p[0])
}

// TransactionID returns the transaction ID byte slice identified in this
// packet.
func (p packet) TransactionID() []byte {
	// If packet is too short to contain a transaction ID,
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

// Options parses a packet's options and returns them as a slice containing
// both an OptionCode type and its raw data value.  Options are returned in
// the order they are placed in the packet.
func (p packet) Options() []option {
	// Skip message type and transaction ID
	return parseOptions(p[4:])
}

// newPacket creates a new packet from an input message type, transaction ID,
// and options slice.  The resulting packet can be used to send a request to
// a DHCP server, or a response to DHCP client.
//
// The transaction ID must be exactly 3 bytes, or an error will be returned.
func newPacket(mt MessageType, txID []byte, options []option) (packet, error) {
	// Transaction ID must always be 3 bytes
	if len(txID) != 3 {
		return nil, errInvalidTransactionID
	}

	// If no options, allocate only enough space for message type
	// and transaction ID
	if len(options) == 0 {
		p := make(packet, 4)
		p[0] = byte(mt)
		copy(p[1:4], txID[:])
		return p, nil
	}

	// Calculate size of packet so the entire packet can be allocated
	// at once

	// 1 byte: message type
	// 3 bytes: transaction ID
	i := 4
	for _, o := range options {
		// 2 bytes: option code
		// 2 bytes: option length
		// N bytes: option data
		i += 2 + 2 + len(o.Data)
	}

	// Allocate packet and fill basic fields
	p := make(packet, i, i)
	p[0] = byte(mt)
	copy(p[1:4], txID[:])

	// Copy options into packet, advancing index to copy options data into
	// proper indices
	i = 4
	for _, o := range options {
		// 2 bytes: option code
		binary.BigEndian.PutUint16(p[i:i+2], uint16(o.Code))
		i += 2

		// 2 bytes: option length
		binary.BigEndian.PutUint16(p[i:i+2], uint16(len(o.Data)))
		i += 2

		// N bytes: option data
		copy(p[i:i+len(o.Data)], o.Data)
		i += len(o.Data)
	}

	return p, nil
}
