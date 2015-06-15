package dhcp6

import (
	"encoding/binary"
	"errors"
	"time"
)

var (
	// errInvalidIAPD is returned when a byte slice does not contain
	// enough bytes to parse a valid IAPD value.
	errInvalidIAPD = errors.New("not enough bytes for valid IAPD")
)

// IAPD represents an Identity Association for Prefix Delegation, as
// defined in RFC 3633, Section 9.
//
// Multiple IAPDs may be present in a single DHCP request.
type IAPD struct {
	// IAID specifies a DHCP identity association identifier.  The IAID
	// is a unique, client-generated identifier.
	IAID [4]byte

	// T1 specifies how long a requesting router will wait to contact a
	// delegating router, to extend the lifetimes of the prefixes delegated
	// to this IAPD, by the delegating router.
	T1 time.Duration

	// T2 specifies how long a requesting router will wait to contact any
	// available delegating router, to extend the lifetimes of the prefixes
	// delegated to this IAPD.
	T2 time.Duration

	// Options specifies a map of DHCP options specific to this IAPD.
	// Its methods can be used to retrieve data from an incoming IAPD, or send
	// data with an outgoing IAPD.
	Options Options
}

// NewIAPD creates a new IAPD from an IAID, T1 and T2 durations, and an
// Options map.  If an Options map is not specified, a new one will be
// allocated.
func NewIAPD(iaid [4]byte, t1 time.Duration, t2 time.Duration, options Options) *IAPD {
	if options == nil {
		options = make(Options)
	}

	return &IAPD{
		IAID:    iaid,
		T1:      t1,
		T2:      t2,
		Options: options,
	}
}

// Bytes implements Byteser, and allocates a byte slice containing the data
// from a IAPD.
func (i *IAPD) Bytes() []byte {
	// 4 bytes: IAID
	// 4 bytes: T1
	// 4 bytes: T2
	// N bytes: options slice byte count
	opts := i.Options.enumerate()
	b := make([]byte, 12+opts.count())

	copy(b[0:4], i.IAID[:])
	binary.BigEndian.PutUint32(b[4:8], uint32(i.T1/time.Second))
	binary.BigEndian.PutUint32(b[8:12], uint32(i.T2/time.Second))
	opts.write(b[12:])

	return b
}

// parseIAPD attempts to parse an input byte slice as a IAPD.
func parseIAPD(b []byte) (*IAPD, error) {
	// IAPD must contain at least an IAID, T1, and T2.
	if len(b) < 12 {
		return nil, errInvalidIAPD
	}

	iaid := [4]byte{}
	copy(iaid[:], b[0:4])

	options, err := parseOptions(b[12:])
	if err != nil {
		return nil, err
	}

	return &IAPD{
		IAID:    iaid,
		T1:      time.Duration(binary.BigEndian.Uint32(b[4:8])) * time.Second,
		T2:      time.Duration(binary.BigEndian.Uint32(b[8:12])) * time.Second,
		Options: options,
	}, nil
}
