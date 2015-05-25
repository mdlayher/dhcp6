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
type IANA []byte

// IAID returns an identity association identifier, which is a value generated
// by a client, chosen to be unique among other IAs for that client.  An IAID
// must always produce the same value across restarts of a client.
func (i IANA) IAID() []byte {
	// Too short to contain IAID
	if len(i) < 4 {
		return nil
	}

	return i[0:4]
}

// T1 returns a duration which indicates how long a DHCP client will wait to
// contact the server, to extend the lifetimes of the addresses assigned to
// this IANA by this server.
func (i IANA) T1() time.Duration {
	// Too short to contain T1
	if len(i) < 8 {
		return 0
	}

	return time.Duration(binary.BigEndian.Uint32(i[4:8])) * time.Second
}

// T2 returns a duration which indicates how long a DHCP client will wait to
// contact any server, to extend the lifetimes of the addresses assigned to
// this IANA by any server.
func (i IANA) T2() time.Duration {
	// Too short to contain T2
	if len(i) < 12 {
		return 0
	}

	return time.Duration(binary.BigEndian.Uint32(i[8:12])) * time.Second
}

// Options parses the Options map associated with this IANA.  The Options
// may contain additional information regarding this IANA.
func (i IANA) Options() Options {
	options := parseOptions(i[12:])

	opt := make(Options, len(options))
	for _, o := range options {
		opt.Add(o.Code, o.Data)
	}

	return opt
}

// parseIANA attempts to parse an input byte slice as a IANA.
func parseIANA(b []byte) (IANA, error) {
	if len(b) < 12 {
		return nil, errInvalidIANA
	}

	return IANA(b), nil
}
