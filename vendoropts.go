package dhcp6

import (
	"io"
)

// A VendorOpts is used by clients and servers to exchange
// VendorOpts information.
type VendorOpts struct {
	// EnterpriseNumber specifies an IANA-assigned vendor Private Enterprise
	// Number.
	EnterpriseNumber uint32

	// An opaque object of option-len octets,
	// interpreted by vendor-specific code on the
	// clients and servers
	Options Options
}

// MarshalBinary allocates a byte slice containing the data from a VendorOpts.
func (v *VendorOpts) MarshalBinary() ([]byte, error) {
	// 4 bytes: EnterpriseNumber
	// N bytes: options slice byte count
	opts := v.Options.enumerate()
	b := newBuffer(make([]byte, 0, 4+opts.count()))
	b.Write32(v.EnterpriseNumber)
	opts.marshal(b)

	return b.Data(), nil
}

// UnmarshalBinary unmarshals a raw byte slice into a VendorOpts.
// If the byte slice does not contain enough data to form a valid
// VendorOpts, io.ErrUnexpectedEOF is returned.
// If option-data are invalid, then ErrInvalidPacket is returned.
func (v *VendorOpts) UnmarshalBinary(p []byte) error {
	b := newBuffer(p)
	// Too short to be valid VendorOpts
	if b.Len() < 4 {
		return io.ErrUnexpectedEOF
	}

	v.EnterpriseNumber = b.Read32()
	if err := (&v.Options).unmarshal(b); err != nil {
		// Invalid options means an invalid RelayMessage
		return ErrInvalidPacket
	}
	return nil
}
