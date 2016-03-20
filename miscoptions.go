package dhcp6

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"net/url"
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

// Data is a raw collection of byte slices, typically carrying user class
// data, vendor class data, or PXE boot file parameters.
type Data [][]byte

// MarshalBinary allocates a byte slice containing the data from a Data
// structure.
func (d Data) MarshalBinary() ([]byte, error) {
	// Count number of bytes needed to allocate at once
	var c int
	for _, dd := range d {
		c += 2 + len(dd)
	}

	b := make([]byte, c)
	var i int

	for _, dd := range d {
		// 2 byte: length of data
		binary.BigEndian.PutUint16(b[i:i+2], uint16(len(dd)))
		i += 2

		// N bytes: actual raw data
		copy(b[i:i+len(dd)], dd)
		i += len(dd)
	}

	return b, nil
}

// UnmarshalBinary unmarshals a raw byte slice into a Data structure.
// Data is packed in the form:
//   - 2 bytes: data length
//   - N bytes: raw data
func (d *Data) UnmarshalBinary(b []byte) error {
	data := make(Data, 0)

	// Iterate until not enough bytes remain to parse another length value
	buf := bytes.NewBuffer(b)
	for buf.Len() > 1 {
		data = append(data, buf.Next(int(binary.BigEndian.Uint16(buf.Next(2)))))
	}

	// At least one instance of class data must be present
	if len(data) == 0 {
		return io.ErrUnexpectedEOF
	}

	// If we encounter any trailing bytes, report an error
	if buf.Len() != 0 {
		return io.ErrUnexpectedEOF
	}

	*d = data
	return nil
}

// A URL is a uniform resource locater.  The URL type is provided for
// convenience. It can be used to easily add URLs to an Options map.
type URL url.URL

// MarshalBinary allocates a byte slice containing the data from a URL.
func (u URL) MarshalBinary() ([]byte, error) {
	uu := url.URL(u)
	return []byte(uu.String()), nil
}

// UnmarshalBinary unmarshals a raw byte slice into an URL.
//
// If the byte slice is not an URLv6 address, io.ErrUnexpectedEOF is
// returned.
func (u *URL) UnmarshalBinary(b []byte) error {
	uu, err := url.Parse(string(b))
	if err != nil {
		return err
	}

	*u = URL(*uu)
	return nil
}

// ArchTypes is a slice of ArchType values.  It is provided for convenient
// marshaling and unmarshaling of a slice of ArchType values from an Options
// map.
type ArchTypes []ArchType

// MarshalBinary allocates a byte slice containing the data from ArchTypes.
func (a ArchTypes) MarshalBinary() ([]byte, error) {
	// Allocate a single byte slice at once and pack every two bytes
	// with an element from the ArchTypes slice
	b := make([]byte, len(a)*2)
	for i, j := 0, 0; j < len(a); i, j = i+2, j+1 {
		binary.BigEndian.PutUint16(b[i:i+2], uint16(a[j]))
	}

	return b, nil
}

// UnmarshalBinary unmarshals a raw byte slice into an ArchTypes slice.
//
// If the byte slice is less than 2 bytes in length, or is not a length that
// is divisible by 2, io.ErrUnexpectedEOF is returned.
func (a *ArchTypes) UnmarshalBinary(b []byte) error {
	// Length must be at least 2, and divisible by 2
	if len(b) < 2 || len(b)%2 != 0 {
		return io.ErrUnexpectedEOF
	}

	// Allocate ArchTypes at once and unpack every two bytes into an element
	arch := make(ArchTypes, len(b)/2)
	for i, j := 0, 0; j < len(b)/2; i, j = i+2, j+1 {
		arch[j] = ArchType(binary.BigEndian.Uint16(b[i : i+2]))
	}

	*a = arch
	return nil
}

// A NII is a Client Network Interface Identifier, as defined in RFC 5970,
// Section 3.4.
//
// A NII is used to indicate a client's level of Universal Network Device
// Interface (UNDI) support.
type NII struct {
	// Type specifies a network interface type.
	Type uint8

	// Major specifies the UNDI major revisision which this client supports.
	Major uint8

	// Minor specifies the UNDI minor revision which this client supports.
	Minor uint8
}

// MarshalBinary allocates a byte slice containing the data from a NII.
func (n *NII) MarshalBinary() ([]byte, error) {
	b := make([]byte, 3)

	b[0] = n.Type
	b[1] = n.Major
	b[2] = n.Minor

	return b, nil
}

// UnmarshalBinary unmarshals a raw byte slice into a NII.
//
// If the byte slice is not exactly 3 bytes in length, io.ErrUnexpectedEOF
// is returned.
func (n *NII) UnmarshalBinary(b []byte) error {
	// Length must be exactly 3
	if len(b) != 3 {
		return io.ErrUnexpectedEOF
	}

	n.Type = b[0]
	n.Major = b[1]
	n.Minor = b[2]

	return nil
}

type RelayMessageOption []byte

func (r *RelayMessageOption) MarshalBinary() ([]byte, error) {
	return *r, nil
}

func (r *RelayMessageOption) UnmarshalBinary(b []byte) error {
	*r = make([]byte, len(b))
	copy(*r, b)
	return nil
}

func (r *RelayMessageOption) SetClientServerMessage(p *Packet) error {
	b, err := p.MarshalBinary()
	if err != nil {
		return err
	}

	*r = b
	return nil
}

func (r *RelayMessageOption) SetRelayMessage(p *RelayMessage) error {
	b, err := p.MarshalBinary()
	if err != nil {
		return err
	}

	*r = b
	return nil
}
