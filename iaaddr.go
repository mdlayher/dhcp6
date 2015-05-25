package dhcp6

import (
	"encoding/binary"
	"errors"
	"net"
	"time"
)

var (
	// errInvalidIAAddr is returned when a byte slice does not contain
	// enough bytes to parse a valid IAAddr value.
	errInvalidIAAddr = errors.New("not enough bytes for valid IAAddr")
)

// IAAddr represents an Identity Association Address, as defined in RFC 3315,
// Section 22.6.  DHCP clients use identity assocation addresses (IAAddrs) to
// request IPv6 addresses from a DHCP server, using the lifetimes specified
// in the preferred lifetime and valid lifetime fields.  Multiple IAAddrs may
// be present in a DHCP request, but only enscapsulated within an IANA or
// IATA option's option fields.
type IAAddr struct {
	// The raw byte slice containing the IAAddr, with options stripped
	iaaddr []byte

	// Options map which is marshaled to binary when Bytes is called
	options Options
}

// Bytes returns the underlying byte slice for an IAAddr, as well as a
// byte slice for all options which have been applied to the Options map
// for this IAAddr.
func (i *IAAddr) Bytes() []byte {
	// Enumerate optslice and check byte count
	opts := i.options.enumerate()
	c := opts.count()

	// Allocate correct number of bytes and write options
	buf := make([]byte, c, c)
	opts.write(buf)

	// Return IAAddr with options
	return append(i.iaaddr, buf...)
}

// IP returns the IPv6 address stored within this IAAddr.
func (i *IAAddr) IP() net.IP {
	// Too short to contain IP
	if len(i.iaaddr) < 16 {
		return nil
	}

	return net.IP(i.iaaddr[0:16])
}

// PreferredLifetime returns the preferred lifetime of an IPv6 address,
// in seconds, as described in RFC 2462, Section 5.5.4.  When the preferred
// lifetime of an address expires, the address becomes deprecated.  A deprecated
// address should be used as a source address in existing communications, but
// should not be used in new communications if a non-deprecated address is
// available.  The preferred lifetime of an address must not be greater than its
// valid lifetime.
func (i *IAAddr) PreferredLifetime() time.Duration {
	// Too short to contain preferred lifetime
	if len(i.iaaddr) < 20 {
		return 0
	}

	return time.Duration(binary.BigEndian.Uint32(i.iaaddr[16:20])) * time.Second
}

// ValidLifetime returns the valid lifetime of an IPv6 address in seconds, as
// described in RFC 2462, Section 5.5.4.  When the valid lifetime of an address
// expires, the address becomes invalid and must not be used for further
// communication.
func (i *IAAddr) ValidLifetime() time.Duration {
	// Too short to contain valid lifetime
	if len(i.iaaddr) < 24 {
		return 0
	}

	return time.Duration(binary.BigEndian.Uint32(i.iaaddr[20:24])) * time.Second
}

// Options parses the Options map associated with this IAAddr.  The Options
// may contain additional information regarding this IAAddr.  Options can be
// added, removed, or modified directly via this map.
func (i IAAddr) Options() Options {
	return i.options
}

// parseIAAddr attempts to parse an input byte slice as an IAAddr.
func parseIAAddr(b []byte) (*IAAddr, error) {
	if len(b) < 24 {
		return nil, errInvalidIAAddr
	}

	return &IAAddr{
		iaaddr:  b[:24],
		options: parseOptions(b[24:]),
	}, nil
}
