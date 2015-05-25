package dhcp6

import (
	"encoding/binary"
	"errors"
	"time"
)

var (
	// errInvalidIANA is returned when a byte slice does not contain
	// enough bytes to parse a valid IANA value.
	errInvalidIANA = errors.New("not enough bytes for valid IA_NA")
)

// IANA represents an Identity Association for Non-temporary Addresses, as
// defined in IETF RFC 3315, Section 10.  DHCP clients and servers use
// identity assocations (IAs) to identify, group, and manage a set of
// related IPv6 addresses.  Each IA must be associated with exactly one
// network interface.  Multiple IAs may be present in a DHCP request.
type IANA struct {
	// The raw byte slice containing the IANA, with options stripped
	iana []byte

	// Options map which is marshaled to binary when Bytes is called
	options Options
}

// Bytes returns the underlying byte slice for an IANA, as well as a
// byte slice for all options which have been applied to the Options
// map for this IANA.
func (i *IANA) Bytes() []byte {
	// Enumerate optslice and check byte count
	opts := i.options.enumerate()
	c := opts.count()

	// Allocate correct number of bytes and write options
	buf := make([]byte, c, c)
	opts.write(buf)

	// Return IANA with options
	return append(i.iana, buf...)
}

// IAID returns an identity association identifier, which is a value generated
// by a client, chosen to be unique among other IAs for that client.  An IAID
// must always produce the same value across restarts of a client.
func (i *IANA) IAID() []byte {
	// Too short to contain IAID
	if len(i.iana) < 4 {
		return nil
	}

	return i.iana[0:4]
}

// T1 returns a duration which indicates how long a DHCP client will wait to
// contact the server, to extend the lifetimes of the addresses assigned to
// this IANA by this server.
func (i *IANA) T1() time.Duration {
	// Too short to contain T1
	if len(i.iana) < 8 {
		return 0
	}

	return time.Duration(binary.BigEndian.Uint32(i.iana[4:8])) * time.Second
}

// T2 returns a duration which indicates how long a DHCP client will wait to
// contact any server, to extend the lifetimes of the addresses assigned to
// this IANA by any server.
func (i *IANA) T2() time.Duration {
	// Too short to contain T2
	if len(i.iana) < 12 {
		return 0
	}

	return time.Duration(binary.BigEndian.Uint32(i.iana[8:12])) * time.Second
}

// Options parses the Options map associated with this IANA.  The Options
// may contain additional information regarding this IANA.  Options can be
// added, removed, or modified directly via this map.
func (i IANA) Options() Options {
	return i.options
}

// parseIANA attempts to parse an input byte slice as a IANA.
func parseIANA(b []byte) (*IANA, error) {
	if len(b) < 12 {
		return nil, errInvalidIANA
	}

	return &IANA{
		iana:    b[:12],
		options: parseOptions(b[12:]),
	}, nil
}
