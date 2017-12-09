package dhcp6

import (
	"github.com/mdlayher/dhcp6/util"
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

// MarshalBinary allocates a byte slice containing the data
// from a Packet.
func (p *Packet) MarshalBinary() ([]byte, error) {
	// 1 byte: message type
	// 3 bytes: transaction ID
	// N bytes: options slice byte count
	b := util.NewBuffer(nil)

	b.Write8(uint8(p.MessageType))
	b.WriteBytes(p.TransactionID[:])
	p.Options.Marshal(b)

	return b.Data(), nil
}

// UnmarshalBinary unmarshals a raw byte slice into a Packet.
//
// If the byte slice does not contain enough data to form a valid Packet,
// ErrInvalidPacket is returned.
func (p *Packet) UnmarshalBinary(q []byte) error {
	b := util.NewBuffer(q)
	// Packet must contain at least a message type and transaction ID
	if b.Len() < 4 {
		return ErrInvalidPacket
	}

	p.MessageType = MessageType(b.Read8())
	b.ReadBytes(p.TransactionID[:])

	if err := (&p.Options).Unmarshal(b); err != nil {
		return ErrInvalidPacket
	}
	return nil
}
