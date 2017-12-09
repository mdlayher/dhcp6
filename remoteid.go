package dhcp6

import (
	"encoding/binary"
	"io"
)

// A RemoteIdentifier carries vendor-specific options.
//
// The vendor is indicated in the enterprise-number field.
// The remote-id field may be used to encode, for instance:
// - a "caller ID" telephone number for dial-up connection
// - a "user name" prompted for by a Remote Access Server
// - a remote caller ATM address
// - a "modem ID" of a cable data modem
// - the remote IP address of a point-to-point link
// - a remote X.25 address for X.25 connections
// - an interface or port identifier
type RemoteIdentifier struct {
	// EnterpriseNumber specifies an IANA-assigned vendor Private Enterprise
	// Number.
	EnterpriseNumber uint32

	// The opaque value for the remote-id.
	RemoteID []byte
}

// MarshalBinary allocates a byte slice containing the data
// from a RemoteIdentifier.
func (r *RemoteIdentifier) MarshalBinary() ([]byte, error) {
	// 4 bytes: EnterpriseNumber
	// N bytes: RemoteId
	b := make([]byte, 4, 4+len(r.RemoteID))

	binary.BigEndian.PutUint32(b, r.EnterpriseNumber)
	b = append(b, r.RemoteID...)

	return b, nil
}

// UnmarshalBinary unmarshals a raw byte slice into a RemoteIdentifier.
// If the byte slice does not contain enough data to form a valid
// RemoteIdentifier, io.ErrUnexpectedEOF is returned.
func (r *RemoteIdentifier) UnmarshalBinary(b []byte) error {
	// Too short to be valid RemoteIdentifier
	if len(b) < 5 {
		return io.ErrUnexpectedEOF
	}

	// Extract EnterpriseNumber
	r.EnterpriseNumber = binary.BigEndian.Uint32(b[:4])

	// Extract opaque value as remote-id
	r.RemoteID = make([]byte, len(b[4:]))
	copy(r.RemoteID, b[4:])

	return nil
}
