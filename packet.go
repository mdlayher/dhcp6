package dhcp6

import (
	"bytes"
	"encoding/binary"
)

// Packet represents a raw DHCPv6 packet, using the format described in IETF
// RFC 3315, Section 6.  A Packet has methods which allow easy access to
// its message type, transaction ID, and any options available in the Packet.
type Packet []byte

// MessageType returns the MessageType constant identified in this Packet.
func (p Packet) MessageType() MessageType {
	// Empty packet means no message type
	if len(p) == 0 {
		return 0
	}

	return MessageType(p[0])
}

// TransactionID returns the transaction ID byte slice identified in this
// Packet.
func (p Packet) TransactionID() []byte {
	// If packet is too short to contain a transaction ID,
	// just return a nil ID
	if len(p) < 4 {
		return nil
	}

	return p[1:4]
}

// Option represents an individual DHCP Option, as defined in IETF RFC 3315,
// Section 22.  An Option carries both an OptionCode and its raw Data.  The
// OptionCode can be compared against the set of OptionCode constants provided
// with this package to easily identify a given option.  The format of the
// option data varies depending on the option code.
type Option struct {
	Code OptionCode
	Data []byte
}

// Options parses a Packet's options and returns them as a slice containing
// both an OptionCode type and its raw data value.  Options are returned in
// the order they are placed in the Packet.
func (p Packet) Options() []Option {
	var options []Option

	// Skip message type and transaction ID,
	// ensure packet is long enough to contain options
	var length int
	buf := bytes.NewBuffer(p[4:])
	for buf.Len() > 4 {
		// 2 bytes: option code
		o := Option{}
		o.Code = OptionCode(binary.BigEndian.Uint16(buf.Next(2)))

		// 2 bytes: option length
		length = int(binary.BigEndian.Uint16(buf.Next(2)))

		// If length indicated is zero, skip to next iteration
		if length == 0 {
			continue
		}

		// N bytes: option data
		o.Data = buf.Next(length)

		// If option data has less bytes than indicated by length,
		// discard the option
		if len(o.Data) < length {
			continue
		}

		options = append(options, o)
	}

	return options
}
