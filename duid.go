package dhcp6

import (
	"encoding/binary"
	"errors"
	"net"
	"time"
)

const (
	// ethernet10Mb is the default IANA hardware type used in DUID generation,
	// if a hardware type cannot be parsed from a network interface.
	ethernet10Mb = 1
)

var (
	// ErrParseHardwareType is returned when a valid hardware type could
	// not be found for a given interface.
	ErrParseHardwareType = errors.New("could not parse hardware type for interface")

	// ErrHardwareTypeNotImplemented is returned when HardwareType is not
	// implemented on the current platform.
	ErrHardwareTypeNotImplemented = errors.New("hardware type detection not implemented on this platform")

	// errInvalidDUID is returned when not enough bytes are present
	// to parse a valid DUID from a byte slice.
	errInvalidDUID = errors.New("not enough bytes for valid DUID")

	// errUnknownDUID is returned when an unknown DUID type is
	// encountered, and thus, a DUID cannot be parsed.
	errUnknownDUID = errors.New("unknown DUID type")
)

// DUIDType is a type of DHCP Unique Identifier, as defined in IETF RFC
// 3315, Section 9.  DUIDs are used to uniquely identify a client to a
// server, or vice-versa.
type DUIDType int

// DUIDType constants which indicate DUID-LLT, DUID-EN, or DUID-LL.
// Additional DUID types are defined in IANA's DHCPv6 parameters registry:
// http://www.iana.org/assignments/dhcpv6-parameters/dhcpv6-parameters.xhtml.
const (
	DUIDTypeLLT DUIDType = 1
	DUIDTypeEN  DUIDType = 2
	DUIDTypeLL  DUIDType = 3

	// BUG(mdlayher): add additional DUID types defined by IANA
)

// DUID represents a DHCP Unique Identifier, as defined in IETF RFC
// 3315, Section 9.  A DUID is used by a DHCP server to identify
// unique clients.  A DUID can also be used by a DHCP client to identify
// a unique server, when needed.
//
// The DUID interface represents a generic DUID, but DUIDs can be
// type-asserted to one of three specific types outlined in RFC 3315,
// Section 9.2, 9.3, and 9.4:
//   - DUIDLLT - DUID Based on Link-layer Address Plus Time
//   -  DUIDEN - DUID Assigned by Vendor Based on Enterprise Number
//   -  DUIDLL - DUID Based on Link-layer Address
//
// The specific type of a DUID can be identified using its Type method.
// If further introspection of the DUID is needed, a type switch is
// recommended:
//	switch d := duid.(type) {
//	case dhcp6.DUIDLLT:
//		fmt.Println(d.Time())
//	case dhcp6.DUIDEN:
//		fmt.Println(d.EnterpriseNumber())
//	case dhcp6.DUIDLL:
//		fmt.Println(d.HardwareAddr())
//	}
type DUID interface {
	Byteser
	Type() DUIDType
}

// DUIDLLT represents a DUID Based on Link-layer Address Plus Time [DUID-LLT],
// as defined in IETF RFC 3315, Section 9.2.
//
// This DUID type must only be used with clients and servers with stable,
// persistent storage.  It is the recommended DUID type for all general
// purpose computing devices.
type DUIDLLT []byte

// Bytes implements DUID and Byteser, and returns the entire underlying byte
// slice for a DUIDLLT.
func (d DUIDLLT) Bytes() []byte {
	return []byte(d)
}

// Type implements DUID, and always returns DUIDTypeLLT.
func (d DUIDLLT) Type() DUIDType {
	return DUIDTypeLLT
}

// HardwareType returns an IANA-assigned hardware type, as described in
// IETF RFC 826.
func (d DUIDLLT) HardwareType() []byte {
	return d[2:4]
}

// Time returns the time the DUID was generated in seconds since midnight
// (UTC), January 1, 2000, modulo 2^32.
func (d DUIDLLT) Time() time.Duration {
	return time.Duration(binary.BigEndian.Uint32(d[4:8])) * time.Second
}

// HardwareAddr returns the hardware address for an arbitrary link-layer
// interface on a device, used in generating the DUID-LLT.  This value
// could represent any arbitrary interface on a system, and should not be
// used as a client or server's communicating hardware address.
func (d DUIDLLT) HardwareAddr() net.HardwareAddr {
	return net.HardwareAddr(d[8:])
}

// DUIDEN represents a DUID Assigned by Vendor Based on Enterprise Number
// [DUID-EN], as defined in IETF RFC 3315, Section 9.3.  This DUID type
// uses an IANA-assigned Private Enterprise Number for a given vendor.
type DUIDEN []byte

// Bytes implements DUID and Byteser, and returns the entire underlying byte
// slice for a DUIDEN.
func (d DUIDEN) Bytes() []byte {
	return []byte(d)
}

// Type implements DUID, and always returns DUIDTypeEN.
func (d DUIDEN) Type() DUIDType {
	return DUIDTypeEN
}

// EnterpriseNumber returns a vendor's registerered Private Enterprise
// Number, as assigned by the IANA.
func (d DUIDEN) EnterpriseNumber() int {
	return int(binary.BigEndian.Uint32(d[2:6]))
}

// Identifier returns a unique identifier which is assigned to a device
// at the time it is manufactured.
func (d DUIDEN) Identifier() []byte {
	return d[6:]
}

// DUIDLL represents a DUID Based on Link-layer Address [DUID-LL],
// as defined in IETF RFC 3315, Section 9.4.
//
// This DUID type is recommended for devices with a
// permanently-connected network interface, but without stable,
// persistent storage.
//
// DUIDLL values are generated automatically for Servers which are not
// created with a ServerID, using the hardware type found by HardwareType
// and the hardware address of the listening network interface.
type DUIDLL []byte

// NewDUIDLL generates a new DUIDLL from an input IANA-assigned hardware
// type and a hardware address.
func NewDUIDLL(hardwareType uint16, hardwareAddr net.HardwareAddr) DUIDLL {
	d := make(DUIDLL, 4+len(hardwareAddr))

	// 2 bytes: DUID type (DUID-LL in this case)
	binary.BigEndian.PutUint16(d[0:2], uint16(DUIDTypeLL))
	// 2 bytes: hardware type
	binary.BigEndian.PutUint16(d[2:4], hardwareType)
	// N bytes: hardware address
	copy(d[4:], hardwareAddr)

	return d
}

// Bytes implements DUID and Byteser, and returns the entire underlying byte
// slice for a DUIDLL.
func (d DUIDLL) Bytes() []byte {
	return []byte(d)
}

// Type implements DUID and always returns DUIDTypeLL.
func (d DUIDLL) Type() DUIDType {
	return DUIDTypeLL
}

// HardwareType returns an IANA-assigned hardware type, as described in
// IETF RFC 826.
func (d DUIDLL) HardwareType() []byte {
	return d[2:4]
}

// HardwareAddr returns the hardware address for an arbitrary link-layer
// interface on a device, used in generating the DUID-LL.  This value
// could represent any arbitrary interface on a system, and should not be
// used as a client or server's communicating hardware address.
func (d DUIDLL) HardwareAddr() net.HardwareAddr {
	return net.HardwareAddr(d[4:])
}

// parseDUID returns the correct DUID type of the input byte slice as a
// DUID interface type.
func parseDUID(d []byte) (DUID, error) {
	// DUID must have enough bytes to determine its type
	if len(d) < 2 {
		return nil, errInvalidDUID
	}

	// BUG(mdlayher): add DUID-UUID to this in the future.
	switch DUIDType(binary.BigEndian.Uint16(d[0:2])) {
	case DUIDTypeLLT:
		return DUIDLLT(d), nil
	case DUIDTypeEN:
		return DUIDEN(d), nil
	case DUIDTypeLL:
		return DUIDLL(d), nil
	}

	return nil, errUnknownDUID
}

// interfaceDUID generates a DUIDLL for an input net.Interface, using its
// IANA-assigned hardware type and its hardware address.
func interfaceDUID(ifi *net.Interface) (DUID, error) {
	// Attempt to check for IANA hardware type, default to Ethernet (10Mb)
	// on failure (this relies on syscalls which only work on Linux)
	// Hardware types can be found here:
	// http://www.iana.org/assignments/arp-parameters/arp-parameters.xhtml.
	htype, err := HardwareType(ifi)
	if err != nil {
		// Return syscall errors
		if err != ErrParseHardwareType && err != ErrHardwareTypeNotImplemented {
			return nil, err
		}

		// Use default value if hardware type can't be found or
		// detection isn't implemented
		htype = ethernet10Mb
	}

	return NewDUIDLL(uint16(htype), ifi.HardwareAddr), nil
}
