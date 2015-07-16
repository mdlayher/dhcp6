package dhcp6

import (
	"encoding/binary"
	"io"
	"net"
	"time"
)

// A Preference is a preference value, as defined in RFC 3315, Section 22.8.
//
// A preference value is sent by a server to a client to affect the selection
// of a server by the client.
type Preference uint8

// MarshalBinary allocates a byte slice containing the data from a Preference.
func (p Preference) MarshalBinary() ([]byte, error) {
	return []byte{byte(p)}, nil
}

// UnmarshalBinary unmarshals a raw byte slice into a Preference.
//
// If the byte slice is not exactly 1 byte in length, io.ErrUnexpectedEOF is
// returned.
func (p *Preference) UnmarshalBinary(b []byte) error {
	if len(b) != 1 {
		return io.ErrUnexpectedEOF
	}

	*p = Preference(b[0])
	return nil
}

// An ElapsedTime is a client's elapsed request time value, as defined in RFC
// 3315, Section 22.9.
//
// The duration returned reports the time elapsed during a DHCP transaction,
// as reported by a client.
type ElapsedTime time.Duration

// MarshalBinary allocates a byte slice containing the data from an
// ElapsedTime.
func (t ElapsedTime) MarshalBinary() ([]byte, error) {
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, uint16(time.Duration(t)/10/time.Millisecond))
	return b, nil
}

// UnmarshalBinary unmarshals a raw byte slice into a ElapsedTime.
//
// If the byte slice is not exactly 2 bytes in length, io.ErrUnexpectedEOF is
// returned.
func (t *ElapsedTime) UnmarshalBinary(b []byte) error {
	if len(b) != 2 {
		return io.ErrUnexpectedEOF
	}

	// Time is reported in hundredths of seconds, so we convert it to a more
	// manageable milliseconds
	*t = ElapsedTime(time.Duration(binary.BigEndian.Uint16(b)) * 10 * time.Millisecond)
	return nil
}

// An IP is an IPv6 address.  The IP type is provided for convenience.
// It can be used to easily add IPv6 addresses to an Options map.
type IP net.IP

// MarshalBinary allocates a byte slice containing the data from a IP.
func (i IP) MarshalBinary() ([]byte, error) {
	ip := make([]byte, net.IPv6len)
	copy(ip, i)
	return ip, nil
}

// UnmarshalBinary unmarshals a raw byte slice into an IP.
//
// If the byte slice is not an IPv6 address, io.ErrUnexpectedEOF is
// returned.
func (i *IP) UnmarshalBinary(b []byte) error {
	if len(b) != net.IPv6len {
		return io.ErrUnexpectedEOF
	}

	ip := net.IP(b)
	if ip.To4() != nil {
		return io.ErrUnexpectedEOF
	}

	*i = make(IP, net.IPv6len)
	copy(*i, b)
	return nil
}
