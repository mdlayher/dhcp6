// Package dhcp6 implements a DHCPv6 server, as described in IETF RFC 3315.
//
// Unless otherwise stated, any reference to "DHCP" in this package refers to
// DHCPv6 only.
package dhcp6

import (
	"errors"
)

//go:generate stringer -output=string.go -type=DUIDType,MessageType,Status,OptionCode

// ErrHardwareTypeNotImplemented is returned when HardwareType is not
// implemented on the current platform.
var ErrHardwareTypeNotImplemented = errors.New("hardware type detection not implemented on this platform")

// ErrInvalidDUIDLLTTime is returned when a time before midnight (UTC),
// January 1, 2000 is used in NewDUIDLLT.
var ErrInvalidDUIDLLTTime = errors.New("DUID-LLT time must be after midnight (UTC), January 1, 2000")

// ErrInvalidIAAddrIP is returned when an input net.IP value is not
// recognized as a valid IPv6 address.
var ErrInvalidIAAddrIP = errors.New("IAAddr IP must be an IPv6 address")

// ErrInvalidIAAddrLifetimes is returned when an input preferred
// lifetime is shorter than a valid lifetime parameter.
var ErrInvalidIAAddrLifetimes = errors.New("IAAddr preferred lifetime must be less than valid lifetime")

// ErrInvalidPacket is returned when a byte slice does not contain enough
// data to create a valid Packet.  A Packet must have at least a message type
// and transaction ID.
var ErrInvalidPacket = errors.New("not enough bytes for valid packet")

// ErrParseHardwareType is returned when a valid hardware type could
// not be found for a given interface.
var ErrParseHardwareType = errors.New("could not parse hardware type for interface")

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

// Byteser is implemented by any value that has a Bytes method.  The Bytes
// method is used to return a value in byte slice form.  Byteser can be used
// to add some types directly to an Options map.
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
