// Package dhcp6 implements a DHCPv6 server, as described in IETF RFC 3315.
//
// Unless otherwise stated, any reference to "DHCP" in this package refers to
// DHCPv6 only.
package dhcp6

//go:generate stringer -output=string.go -type=DUIDType,MessageType,Status,OptionCode

// Handler provides an interface which allows structs to act as DHCPv6 server
// handlers.  ServeDHCP implementations receive a copy of the incoming DHCP
// request via the Request parameter, and allow outgoing communication via
// the Responser.
//
// ServeDHCP implementations can choose to write a response packet using the
// Responser interface, or choose to not write anything at all.  If no packet
// is sent back to the client, it may choose to back off and retry, or attempt
// to pursue communication with other DHCP servers.
type Handler interface {
	ServeDHCP(Responser, *Request)
}

// HandlerFunc is an adapter type which allows the use of normal functions as
// DHCP handlers.  If f is a function with the appropriate signature,
// HandlerFunc(f) is a Handler struct that calls f.
type HandlerFunc func(Responser, *Request)

// ServeDHCP calls f(w, r), allowing regular functions to implement Handler.
func (f HandlerFunc) ServeDHCP(w Responser, r *Request) {
	f(w, r)
}

// Byteser is an interface which structs may implement if they can marshal
// themselves into a byte slice form.  Byteser is used to allow some types
// to be inserted directly into an Options map.
type Byteser interface {
	Bytes() []byte
}

// Responser provides an interface which allows a DHCP handler to construct
// and write a DHCP packet.  In addition, the server automatically handles
// copying certain parameters from a client Request to a Responser's Options
// and outbound packet, including:
//   - Transaction ID
//   - Client ID (OptionClientID)
//   - Server ID (OptionServerID)
//
// BUG(mdlayher): the interface for Responser will most likely change.
type Responser interface {
	// Options returns the Options map that will be sent to a client
	// after a call to Send.  Changing options after a call to Send
	// has no effect.
	Options() Options

	// Send generates a DHCP response packet using the input message type
	// and any options set by Options.  Send returns the number of bytes
	// sent and any errors which occurred.
	Send(MessageType) (int, error)
}
