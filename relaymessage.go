package dhcp6

// Packet represents a raw DHCPv6 relay message, using the format described in RFC 3315,
// Section 7.
// Relay Agent/Server Message Formats
//
//    Relay agents exchange messages with servers to relay messages between
//    clients and servers that are not connected to the same link.
//
//    All values in the message header and in options are in network byte
//    order.
//
//    Options are stored serially in the options field, with no padding
//    between the options.  Options are byte-aligned but are not aligned in
//    any other way such as on 2 or 4 byte boundaries.
//
//    There are two relay agent messages, which share the following format:
//
//        0                   1                   2                   3
//        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//       |    msg-type   |   hop-count   |                               |
//       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               |
//       |                                                               |
//       |                         link-address                          |
//       |                                                               |
//       |                               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-|
//       |                               |                               |
//       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               |
//       |                                                               |
//       |                         peer-address                          |
//       |                                                               |
//       |                               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-|
//       |                               |                               |
//       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               |
//       .                                                               .
//       .            options (variable number and length)   ....        .
//       |                                                               |
//       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
//    The following sections describe the use of the Relay Agent message
//    header.
type RelayMessage struct {
	// RELAY-FORW or RELAY-REPL only
	MessageType MessageType

	// Number of relay agents that have relayed this
	// message.
	Hopcount uint8

	// A global or site-local address that will be used by
	// the server to identify the link on which the client
	// is located.
	LinkAddress [16]byte

	// The address of the client or relay agent from which
	// the message to be relayed was received.
	PeerAddress [16]byte

	// Options specifies a map of DHCP options.  Its methods can be used to
	// retrieve data from an incoming packet, or send data with an outgoing
	// packet.
	// MUST include a "Relay Message option" (see
	// section 22.10); MAY include other options added by
	// the relay agent.
	Options Options
}

// MarshalBinary allocates a byte slice containing the data
// from a Packet.
func (p *RelayMessage) MarshalBinary() ([]byte, error) {
	// 1 byte: message type
	// 1 byte: hop-count
	// 16 bytes: link-address
	// 16 bytes: peer-address
	// N bytes: options slice byte count

	opts := p.Options.enumerate()
	b := make([]byte, 34+opts.count())

	b[0] = byte(p.MessageType)
	b[1] = byte(p.Hopcount)
	copy(b[2:18], p.LinkAddress[:])
	copy(b[18:34], p.PeerAddress[:])
	opts.write(b[34:])

	return b, nil
}

// UnmarshalBinary unmarshals a raw byte slice into a Packet.
//
// If the byte slice does not contain enough data to form a valid Packet,
// ErrInvalidPacket is returned.
func (p *RelayMessage) UnmarshalBinary(b []byte) error {
	// Packet must contain at least message type, hop-count, link-address and peer-address
	if len(b) < 34 {
		return ErrInvalidPacket
	}

	p.MessageType = MessageType(b[0])
	p.Hopcount = uint8(b[1])

	p.LinkAddress = [16]byte{}
	copy(p.LinkAddress[:], b[2:18])

	p.PeerAddress = [16]byte{}
	copy(p.PeerAddress[:], b[18:34])

	options, err := parseOptions(b[34:])
	if err != nil {
		// Invalid options means an invalid packet
		return ErrInvalidPacket
	}
	p.Options = options

	return nil
}
