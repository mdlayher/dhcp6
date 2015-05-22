package dhcp6

import (
	"encoding/binary"
	"net"
	"time"
)

// Request represents a processed DHCP request received by a server.
// Its struct members contain information regarding the request's message
// type, transaction ID, client ID, options, etc.
type Request struct {
	// DHCP message type, such as Solicit, Request, or Renew.
	MessageType MessageType

	// Unique transaction ID, which should be preserved across
	// multiple requests to the same DHCP server.  ServeDHCP
	// implementations must manually verify that the same
	// transaction ID is used.
	TransactionID []byte

	// Slice of options sent by client, carrying additional
	// information or requesting additional information from
	// the server.
	Options []Option

	// Unique client ID, represented by a DHCP Unique Identifier,
	// or DUID.  A DUID may not be present for all requests, in
	// which case, ClientID is nil.  See the documentation for
	// DUID for more details.
	ClientID DUID

	// Time elapsed during a DHCP transaction, as reported by the
	// client.
	Elapsed time.Duration

	// Length of the DHCP request, in bytes.
	Length int64

	// Network address which was used to contact the DHCP server.
	RemoteAddr string

	packet Packet
}

// newRequest creates a new *Request from an input Packet and UDP address.
// It populates the basic struct members which can be used in a DHCP handler,
// and also parses some well-known options into a simpler form.
func newRequest(p Packet, remoteAddr *net.UDPAddr) *Request {
	r := &Request{
		MessageType:   p.MessageType(),
		TransactionID: p.TransactionID(),
		Options:       p.Options(),
		Length:        int64(len(p)),
		RemoteAddr:    remoteAddr.String(),

		packet: p,
	}

	// Parse and iterate all options from packet to gather additional
	// fields for Request
	for _, o := range r.Options {
		switch o.Code {
		case OptionClientID:
			r.ClientID = parseDUID(o.Data)
		case OptionElapsedTime:
			// Time is reported in hundredths of seconds, so we convert
			// it to a more manageable milliseconds
			r.Elapsed = time.Duration(binary.BigEndian.Uint16(o.Data)) * 10 * time.Millisecond
		}
	}

	return r
}
