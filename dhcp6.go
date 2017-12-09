// Package dhcp6 implements a DHCPv6 server, as described in RFC 3315.
//
// Unless otherwise stated, any reference to "DHCP" in this package refers to
// DHCPv6 only.
package dhcp6

import (
	"errors"
)

//go:generate stringer -output=string.go -type=ArchType,DUIDType,MessageType,Status,OptionCode

var (
	// ErrHardwareTypeNotImplemented is returned when HardwareType is not
	// implemented on the current platform.
	ErrHardwareTypeNotImplemented = errors.New("hardware type detection not implemented on this platform")

	// ErrInvalidDUIDLLTTime is returned when a time before midnight (UTC),
	// January 1, 2000 is used in NewDUIDLLT.
	ErrInvalidDUIDLLTTime = errors.New("DUID-LLT time must be after midnight (UTC), January 1, 2000")

	// ErrInvalidIP is returned when an input net.IP value is not recognized as a
	// valid IPv6 address.
	ErrInvalidIP = errors.New("IP must be an IPv6 address")

	// ErrInvalidLifetimes is returned when an input preferred lifetime is shorter
	// than a valid lifetime parameter.
	ErrInvalidLifetimes = errors.New("preferred lifetime must be less than valid lifetime")

	// ErrInvalidPacket is returned when a byte slice does not contain enough
	// data to create a valid Packet.  A Packet must have at least a message type
	// and transaction ID.
	ErrInvalidPacket = errors.New("not enough bytes for valid packet")

	// ErrParseHardwareType is returned when a valid hardware type could
	// not be found for a given interface.
	ErrParseHardwareType = errors.New("could not parse hardware type for interface")

	// ErrOptionNotPresent is returned when a requested opcode is not in
	// the packet.
	ErrOptionNotPresent = errors.New("option code not present in packet")
)
