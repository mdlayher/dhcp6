package dhcp6

import (
	"errors"
)

var (
	// ErrMalformedPacket is returned when a byte slice does not contain enough
	// data to create a valid Packet.  A Packet must have at least a message type
	// and transaction ID.
	ErrMalformedPacket = errors.New("malformed packet")

	// ErrInvalidTransactionID is returned when a transaction ID not exactly
	// 3 bytes in length.
	ErrInvalidTransactionID = errors.New("transaction ID must be exactly 3 bytes")
)

// Packet represents a raw DHCPv6 packet, using the format described in IETF
// RFC 3315, Section 6.  A Packet has methods which allow easy access to
// its message type, transaction ID, and any options available in the Packet.
//
// The Packet type is typically only needed for low-level operations within the
// server, or in tests.
type Packet []byte

// MessageType returns the MessageType constant identified in this Packet.
// If the Packet is empty, ErrMalformedPacket is returned.
func (p Packet) MessageType() (MessageType, error) {
	// Empty Packet means no message type
	if len(p) == 0 {
		return 0, ErrMalformedPacket
	}

	return MessageType(p[0]), nil
}

// TransactionID returns the transaction ID byte slice identified in this
// Packet.  If the Packet is too short to contain a transaction ID,
// ErrMalformedPacket is returned.
func (p Packet) TransactionID() ([]byte, error) {
	// If Packet is too short to contain a transaction ID,
	// just return a nil ID
	if len(p) < 4 {
		return nil, ErrMalformedPacket
	}

	return p[1:4], nil
}

// option represents an individual DHCP Option, as defined in IETF RFC 3315,
// Section 22.  An Option carries both an OptionCode and its raw Data.  The
// format of option data varies depending on the option code.
type option struct {
	Code OptionCode
	Data []byte
}

// Options parses a Packet's options and returns them as an Options map.
// If the Packet is too short to contain any options, ErrMalformedPacket
// is returned.
func (p Packet) Options() (Options, error) {
	if len(p) < 4 {
		return nil, ErrMalformedPacket
	}

	// Skip message type and transaction ID
	return parseOptions(p[4:]), nil
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
		return nil, ErrInvalidTransactionID
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

// ParsePacket parses a raw byte slice into a Packet.  If the byte slice
// does not contain enough data to form a valid Packet, ErrMalformedPacket
// is returned.
func ParsePacket(b []byte) (Packet, error) {
	p := Packet(b)

	if _, err := p.MessageType(); err != nil {
		return nil, err
	}

	// If packet contains a transaction ID, it is long enough to contain
	// options, even though options may be entirely empty.  Thus, we do
	// not need to check for options.
	_, err := p.TransactionID()
	return p, err
}
