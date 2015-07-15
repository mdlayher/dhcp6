package dhcp6

import (
	"io"
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
