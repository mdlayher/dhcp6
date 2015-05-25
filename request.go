package dhcp6

import (
	"net"
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

	// Map of options sent by client, carrying additional
	// information or requesting additional information from
	// the server.  Its methods can be used to check for and parse
	// additional information relating to a request.
	Options Options

	// Length of the DHCP request, in bytes.
	Length int64

	// Network address which was used to contact the DHCP server.
	RemoteAddr string

	packet packet
}

// newServerRequest creates a new *Request from an input packet and UDP address.
// It populates the basic struct members which can be used in a DHCP handler,
// and also parses some well-known options into a simpler form.
//
// It is only intended to be used by the server component and tests.
func newServerRequest(p packet, remoteAddr *net.UDPAddr) *Request {
	return &Request{
		MessageType:   p.MessageType(),
		TransactionID: p.TransactionID(),
		Options:       p.Options(),
		Length:        int64(len(p)),
		RemoteAddr:    remoteAddr.String(),

		packet: p,
	}
}
