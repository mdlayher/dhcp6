package dhcp6

import (
	"encoding/binary"
	"errors"
	"net"
	"time"
)

var (
	// ErrInvalidIAAddrIP is returned when an input net.IP value is not
	// recognized as a valid IPv6 address.
	ErrInvalidIAAddrIP = errors.New("IAAddr IP must be an IPv6 address")

	// ErrInvalidIAAddrLifetimes is returned when an input preferred
	// lifetime is shorter than a valid lifetime parameter.
	ErrInvalidIAAddrLifetimes = errors.New("IAAddr preferred lifetime must be less than valid lifetime")

	// errInvalidIAAddr is returned when a byte slice does not contain
	// enough bytes to parse a valid IAAddr value.
	errInvalidIAAddr = errors.New("not enough bytes for valid IAAddr")
)

// IAAddr represents an Identity Association Address, as defined in RFC 3315,
// Section 22.6.
//
// DHCP clients use identity assocation addresses (IAAddrs) to request IPv6
// addresses from a DHCP server, using the lifetimes specified in the preferred
// lifetime and valid lifetime fields.  Multiple IAAddrs may be present in a
// single DHCP request, but only enscapsulated within an IANA or IATA options
// field.
type IAAddr struct {
	IP                net.IP
	PreferredLifetime time.Duration
	ValidLifetime     time.Duration
	Options           Options
}

// NewIAAddr creates a new IAAddr from an IPv6 address, preferred and valid lifetime
// durations, and an optional Options map.
//
// The IP must be exactly 16 bytes, the correct length for an IPv6 address.
// The preferred lifetime duration must be less than the valid lifetime
// duration.  Failure to meet either of these conditions will result in an error.
// If an Options map is not specified, a new one will be allocated.
func NewIAAddr(ip net.IP, preferred time.Duration, valid time.Duration, options Options) (*IAAddr, error) {
	// From documentation: If ip is not an IPv4 address, To4 returns nil.
	if ip.To4() != nil {
		return nil, ErrInvalidIAAddrIP
	}

	// Preferred lifetime must always be less than valid lifetime.
	if preferred > valid {
		return nil, ErrInvalidIAAddrLifetimes
	}

	// If no options set, make empty map
	if options == nil {
		options = make(Options)
	}

	return &IAAddr{
		IP:                ip,
		PreferredLifetime: preferred,
		ValidLifetime:     valid,
		Options:           options,
	}, nil
}

// Bytes implements Byteser, and returns the underlying byte slice for an
// IAAddr, appended with a byte slice of all options which have been applied
// to the Options map for this IAAddr.
func (i *IAAddr) Bytes() []byte {
	// 16 bytes: IPv6 address
	//  4 bytes: preferred lifetime
	//  4 bytes: valid lifetime
	//  N bytes: options
	opts := i.Options.enumerate()
	b := make([]byte, 24+opts.count())

	copy(b[0:16], i.IP)
	binary.BigEndian.PutUint32(b[16:20], uint32(i.PreferredLifetime/time.Second))
	binary.BigEndian.PutUint32(b[20:24], uint32(i.ValidLifetime/time.Second))
	opts.write(b[24:])

	return b
}

// parseIAAddr attempts to parse an input byte slice as an IAAddr.
func parseIAAddr(b []byte) (*IAAddr, error) {
	if len(b) < 24 {
		return nil, errInvalidIAAddr
	}

	ip := make(net.IP, 16)
	copy(ip, b[0:16])

	preferred := time.Duration(binary.BigEndian.Uint32(b[16:20])) * time.Second
	valid := time.Duration(binary.BigEndian.Uint32(b[20:24])) * time.Second

	// Preferred lifetime must always be less than valid lifetime.
	if preferred > valid {
		return nil, ErrInvalidIAAddrLifetimes
	}

	return &IAAddr{
		IP:                ip,
		PreferredLifetime: preferred,
		ValidLifetime:     valid,
		Options:           parseOptions(b[24:]),
	}, nil
}
