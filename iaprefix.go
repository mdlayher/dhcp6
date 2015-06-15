package dhcp6

import (
	"encoding/binary"
	"errors"
	"net"
	"time"
)

var (
	// errInvalidIAPrefix is returned when a byte slice does not contain
	// enough bytes to parse a valid IAPrefix value.
	errInvalidIAPrefix = errors.New("not enough bytes for valid IAPrefix")
)

// IAPrefix represents an Identity Association Prefix, as defined in RFC 3633,
// Section 10.
//
// Routers may use identity assocation prefixes (IAPrefixes) to request IPv6
// prefixes to assign individual address to IPv6 clients, using the lifetimes
// specified in the preferred lifetime and valid lifetime fields.  Multiple
// IAPrefixes may be present in a single DHCP request, but only enscapsulated
// within an IAPD's options.
type IAPrefix struct {
	// PreferredLifetime specifies the preferred lifetime of an IPv6 prefix.
	// When the preferred lifetime of a prefix expires, the prefix becomes
	// deprecated, and addresses from the prefix should not be used in new
	// communications.
	//
	// The preferred lifetime of a prefix must not be greater than its valid
	// lifetime.
	PreferredLifetime time.Duration

	// ValidLifetime specifies the valid lifetime of an IPv6 prefix.  When the
	// valid lifetime of a prefix expires, addresses from the prefix the address
	// should not be used for any further communication.
	//
	// The valid lifetime of a prefix must be greater than its preferred
	// lifetime.
	ValidLifetime time.Duration

	// PrefixLength specifies the length in bits of an IPv6 address prefix, such
	// as 32, 64, etc.
	PrefixLength uint8

	// Prefix specifies the IPv6 address prefix from which IPv6 addresses can
	// be allocated.
	Prefix net.IP

	// Options specifies a map of DHCP options specific to this IAPrefix.
	// Its methods can be used to retrieve data from an incoming IAPrefix, or
	// send data with an outgoing IAPrefix.
	Options Options
}

// NewIAPrefix creates a new IAPrefix from preferred and valid lifetime
// durations, an IPv6 prefix length, an IPv6 prefix, and an optional Options
// map.
//
// The preferred lifetime duration must be less than the valid lifetime
// duration.  The IPv6 prefix must be exactly 16 bytes, the correct length
// for an IPv6 address.  Failure to meet either of these conditions will result
// in an error.  If an Options map is not specified, a new one will be
// allocated.
func NewIAPrefix(preferred time.Duration, valid time.Duration, prefixLength uint8, prefix net.IP, options Options) (*IAPrefix, error) {
	// Preferred lifetime must always be less than valid lifetime.
	if preferred > valid {
		return nil, ErrInvalidLifetimes
	}

	// From documentation: If ip is not an IPv4 address, To4 returns nil.
	if prefix.To4() != nil {
		return nil, ErrInvalidIP
	}

	// If no options set, make empty map
	if options == nil {
		options = make(Options)
	}

	return &IAPrefix{
		PreferredLifetime: preferred,
		ValidLifetime:     valid,
		PrefixLength:      prefixLength,
		Prefix:            prefix,
		Options:           options,
	}, nil
}

// Bytes implements Byteser, and allocates a byte slice containing the data
// from a IAPrefix.
func (i *IAPrefix) Bytes() []byte {
	//  4 bytes: preferred lifetime
	//  4 bytes: valid lifetime
	//  1 byte : prefix length
	// 16 bytes: IPv6 prefix
	//  N bytes: options
	opts := i.Options.enumerate()
	b := make([]byte, 25+opts.count())

	binary.BigEndian.PutUint32(b[0:4], uint32(i.PreferredLifetime/time.Second))
	binary.BigEndian.PutUint32(b[4:8], uint32(i.ValidLifetime/time.Second))
	b[8] = i.PrefixLength
	copy(b[9:25], i.Prefix)
	opts.write(b[25:])

	return b
}

// parseIAPrefix attempts to parse an input byte slice as an IAPrefix.
func parseIAPrefix(b []byte) (*IAPrefix, error) {
	// IAPrefix must at least contain lifetimes, prefix length, and prefix
	if len(b) < 25 {
		return nil, errInvalidIAPrefix
	}

	preferred := time.Duration(binary.BigEndian.Uint32(b[0:4])) * time.Second
	valid := time.Duration(binary.BigEndian.Uint32(b[4:8])) * time.Second

	// Preferred lifetime must always be less than valid lifetime.
	if preferred > valid {
		return nil, ErrInvalidLifetimes
	}

	prefixLength := b[8]

	prefix := make(net.IP, 16)
	copy(prefix, b[9:25])

	options, err := parseOptions(b[25:])
	if err != nil {
		return nil, err
	}

	return &IAPrefix{
		PreferredLifetime: preferred,
		ValidLifetime:     valid,
		PrefixLength:      prefixLength,
		Prefix:            prefix,
		Options:           options,
	}, nil
}
