package dhcp6

import (
	"bytes"
	"encoding"
	"encoding/binary"
	"errors"
	"sort"
)

var (
	// errInvalidOptions is returned when invalid options data is encountered
	// during parsing.  The data could report an incorrect length or have
	// trailing bytes which are not part of the option.
	errInvalidOptions = errors.New("invalid options data")

	// errInvalidOptionRequest is returned when a valid duration cannot be parsed
	// from OptionOptionRequest, because an odd number of bytes are present.
	errInvalidOptionRequest = errors.New("invalid option value for OptionRequestOption")
)

// Options is a map of OptionCode keys with a slice of byte slice values.
//
// Its methods can be used to easily check for and parse additional information
// from a client request. If raw data is needed, the map can be accessed
// directly.
//
// All Options methods return ErrOptionsNotPresent if the value is not in the
// map. Any other errors occur if the value is present, but invalid (e.g.
// malformed).
type Options map[OptionCode][][]byte

// Add adds a new OptionCode key and BinaryMarshaler struct's bytes to the
// Options map.
func (o Options) Add(key OptionCode, value encoding.BinaryMarshaler) error {
	// Special case: since OptionRapidCommit actually has zero length, it is
	// possible for an option key to appear with no value.
	if value == nil {
		o.addRaw(key, nil)
		return nil
	}

	b, err := value.MarshalBinary()
	if err != nil {
		return err
	}

	o.addRaw(key, b)
	return nil
}

// addRaw adds a new OptionCode key and raw value byte slice to the
// Options map.
func (o Options) addRaw(key OptionCode, value []byte) {
	o[key] = append(o[key], value)
}

// Get attempts to retrieve all values specified by an OptionCode key.
//
// If a value is found, get returns a non-nil [][]byte and nil. If it is not
// found, Get returns nil and ErrOptionNotPresent.
func (o Options) Get(key OptionCode) ([][]byte, error) {
	// Check for value by key.
	v, ok := o[key]
	if !ok {
		return nil, ErrOptionNotPresent
	}

	// Some options can actually have zero length (OptionRapidCommit), so
	// just return an empty byte slice if this is the case.
	if len(v) == 0 {
		return [][]byte{{}}, nil
	}
	return v, nil
}

// GetOne attempts to retrieve the first and only value specified by an
// OptionCode key. GetOne should only be used for OptionCode keys that must
// have at most one value.
//
// GetOne works just like Get, but if there is more than one value for the
// OptionCode key, ErrInvalidPacket will be returned.
func (o Options) GetOne(key OptionCode) ([]byte, error) {
	vv, err := o.Get(key)
	if err != nil {
		return nil, err
	}

	if len(vv) != 1 {
		return nil, ErrInvalidPacket
	}
	return vv[0], nil
}

// ClientID returns the Client Identifier Option value, as described in RFC
// 3315, Section 22.2.
//
// The DUID returned allows unique identification of a client to a server.
func (o Options) ClientID() (DUID, error) {
	v, err := o.GetOne(OptionClientID)
	if err != nil {
		return nil, err
	}

	return parseDUID(v)
}

// ServerID returns the Server Identifier Option value, as described in RFC
// 3315, Section 22.3.
//
// The DUID returned allows unique identification of a server to a client.
func (o Options) ServerID() (DUID, error) {
	v, err := o.GetOne(OptionServerID)
	if err != nil {
		return nil, err
	}

	return parseDUID(v)
}

// IANA returns the Identity Association for Non-temporary Addresses Option
// value, as described in RFC 3315, Section 22.4.
//
// Multiple IANA values may be present in a single DHCP request.
func (o Options) IANA() ([]*IANA, error) {
	vv, err := o.Get(OptionIANA)
	if err != nil {
		return nil, err
	}

	// Parse each IA_NA value
	iana := make([]*IANA, len(vv))
	for i := range vv {
		iana[i] = &IANA{}
		if err := iana[i].UnmarshalBinary(vv[i]); err != nil {
			return nil, err
		}
	}
	return iana, nil
}

// IATA returns the Identity Association for Temporary Addresses Option
// value, as described in RFC 3315, Section 22.5.
//
// Multiple IATA values may be present in a single DHCP request.
func (o Options) IATA() ([]*IATA, error) {
	vv, err := o.Get(OptionIATA)
	if err != nil {
		return nil, err
	}

	// Parse each IA_NA value
	iata := make([]*IATA, len(vv))
	for i := range vv {
		iata[i] = &IATA{}
		if err := iata[i].UnmarshalBinary(vv[i]); err != nil {
			return nil, err
		}
	}
	return iata, nil
}

// IAAddr returns the Identity Association Address Option value, as described
// in RFC 3315, Section 22.6.
//
// The IAAddr option must always appear encapsulated in the Options map of a
// IANA or IATA option.  Multiple IAAddr values may be present in a single DHCP
// request.
func (o Options) IAAddr() ([]*IAAddr, error) {
	vv, err := o.Get(OptionIAAddr)
	if err != nil {
		return nil, err
	}

	iaAddr := make([]*IAAddr, len(vv))
	for i := range vv {
		iaAddr[i] = &IAAddr{}
		if err := iaAddr[i].UnmarshalBinary(vv[i]); err != nil {
			return nil, err
		}
	}
	return iaAddr, nil
}

// OptionRequest returns the Option Request Option value, as described in RFC
// 3315, Section 22.7.
//
// The slice of OptionCode values indicates the options a DHCP client is
// interested in receiving from a server.
func (o Options) OptionRequest() (OptionRequestOption, error) {
	v, err := o.GetOne(OptionORO)
	if err != nil {
		return nil, err
	}

	var oro OptionRequestOption
	err = oro.UnmarshalBinary(v)
	return oro, err
}

// Preference returns the Preference Option value, as described in RFC 3315,
// Section 22.8.
//
// The integer preference value is sent by a server to a client to affect the
// selection of a server by the client.
func (o Options) Preference() (Preference, error) {
	v, err := o.GetOne(OptionPreference)
	if err != nil {
		return 0, err
	}

	var p Preference
	err = (&p).UnmarshalBinary(v)
	return p, err
}

// ElapsedTime returns the Elapsed Time Option value, as described in RFC 3315,
// Section 22.9.
//
// The time.Duration returned reports the time elapsed during a DHCP
// transaction, as reported by a client.
func (o Options) ElapsedTime() (ElapsedTime, error) {
	v, err := o.GetOne(OptionElapsedTime)
	if err != nil {
		return 0, err
	}

	var t ElapsedTime
	err = (&t).UnmarshalBinary(v)
	return t, err
}

// RelayMessageOption returns the Relay Message Option value, as described in RFC 3315,
// Section 22.10.
//
// The RelayMessage option carries a DHCP message in a Relay-forward or
// Relay-reply message.
func (o Options) RelayMessageOption() (RelayMessageOption, error) {
	v, err := o.GetOne(OptionRelayMsg)
	if err != nil {
		return nil, err
	}

	var r RelayMessageOption
	err = (&r).UnmarshalBinary(v)
	return r, err
}

// Authentication returns the Authentication Option value, as described in RFC 3315,
// Section 22.11.
//
// The Authentication option carries authentication information to
// authenticate the identity and contents of DHCP messages.
func (o Options) Authentication() (*Authentication, error) {
	v, err := o.GetOne(OptionAuth)
	if err != nil {
		return nil, err
	}

	a := new(Authentication)
	err = a.UnmarshalBinary(v)
	return a, err
}

// Unicast returns the IP from a Unicast Option value, described in RFC 3315,
// Section 22.12.
//
// The IP return value indicates a server's IPv6 address, which a client may
// use to contact the server via unicast.
func (o Options) Unicast() (IP, error) {
	v, err := o.GetOne(OptionUnicast)
	if err != nil {
		return nil, err
	}

	var ip IP
	err = ip.UnmarshalBinary(v)
	return ip, err
}

// StatusCode returns the Status Code Option value, described in RFC 3315,
// Section 22.13.
//
// The StatusCode return value may be used to determine a code and an
// explanation for the status.
func (o Options) StatusCode() (*StatusCode, error) {
	v, err := o.GetOne(OptionStatusCode)
	if err != nil {
		return nil, err
	}

	s := new(StatusCode)
	err = s.UnmarshalBinary(v)
	return s, err
}

// RapidCommit returns the Rapid Commit Option value, described in RFC 3315,
// Section 22.14.
//
// The boolean return value indicates if OptionRapidCommit was present in the
// Options map, and thus, if Rapid Commit should be used.
func (o Options) RapidCommit() error {
	v, err := o.GetOne(OptionRapidCommit)
	if err != nil {
		return err
	}

	// Data must be completely empty; presence of the Rapid Commit option
	// indicates it is requested.
	if len(v) != 0 {
		return ErrInvalidPacket
	}
	return nil
}

// UserClass returns the User Class Option value, described in RFC 3315,
// Section 22.15.
//
// The Data structure returned contains any raw class data present in
// the option.
func (o Options) UserClass() (Data, error) {
	v, err := o.GetOne(OptionUserClass)
	if err != nil {
		return nil, err
	}

	var d Data
	err = d.UnmarshalBinary(v)
	return d, err
}

// VendorClass returns the Vendor Class Option value, described in RFC 3315,
// Section 22.16.
//
// The VendorClass structure returned contains VendorClass in
// the option.
func (o Options) VendorClass() (*VendorClass, error) {
	v, err := o.GetOne(OptionVendorClass)
	if err != nil {
		return nil, err
	}

	vc := new(VendorClass)
	err = vc.UnmarshalBinary(v)
	return vc, err
}

// VendorOpts returns the Vendor-specific Information Option value, described
// in RFC 3315, Section 22.17.
//
// The VendorOpts structure returned contains Vendor-specific Information data
// present in the option.
func (o Options) VendorOpts() (*VendorOpts, error) {
	v, err := o.GetOne(OptionVendorOpts)
	if err != nil {
		return nil, err
	}

	vo := new(VendorOpts)
	err = vo.UnmarshalBinary(v)
	return vo, err
}

// InterfaceID returns the Interface-Id Option value, described in RFC 3315,
// Section 22.18.
//
// The InterfaceID structure returned contains any raw class data present in
// the option.
func (o Options) InterfaceID() (InterfaceID, error) {
	v, err := o.GetOne(OptionInterfaceID)
	if err != nil {
		return nil, err
	}

	var i InterfaceID
	err = i.UnmarshalBinary(v)
	return i, err
}

// IAPD returns the Identity Association for Prefix Delegation Option value,
// described in RFC 3633, Section 9.
//
// Multiple IAPD values may be present in a a single DHCP request.
func (o Options) IAPD() ([]*IAPD, error) {
	vv, err := o.Get(OptionIAPD)
	if err != nil {
		return nil, err
	}

	// Parse each IA_PD value
	iapd := make([]*IAPD, len(vv))
	for i := range vv {
		iapd[i] = &IAPD{}
		if err := iapd[i].UnmarshalBinary(vv[i]); err != nil {
			return nil, err
		}
	}

	return iapd, nil
}

// IAPrefix returns the Identity Association Prefix Option value, as described
// in RFC 3633, Section 10.
//
// Multiple IAPrefix values may be present in a a single DHCP request.
func (o Options) IAPrefix() ([]*IAPrefix, error) {
	vv, err := o.Get(OptionIAPrefix)
	if err != nil {
		return nil, err
	}

	// Parse each IAPrefix value
	iaPrefix := make([]*IAPrefix, len(vv))
	for i := range vv {
		iaPrefix[i] = &IAPrefix{}
		if err := iaPrefix[i].UnmarshalBinary(vv[i]); err != nil {
			return nil, err
		}
	}

	return iaPrefix, nil
}

// RemoteIdentifier returns the Remote Identifier, described in RFC 4649.
//
// This option may be added by DHCPv6 relay agents that terminate
// switched or permanent circuits and have mechanisms to identify the
// remote host end of the circuit.
func (o Options) RemoteIdentifier() (*RemoteIdentifier, error) {
	v, err := o.GetOne(OptionRemoteIdentifier)
	if err != nil {
		return nil, err
	}

	r := new(RemoteIdentifier)
	err = r.UnmarshalBinary(v)
	return r, err
}

// BootFileURL returns the Boot File URL Option value, described in RFC 5970,
// Section 3.1.
//
// The URL return value contains a URL which may be used by clients to obtain
// a boot file for PXE.
func (o Options) BootFileURL() (*URL, error) {
	v, err := o.GetOne(OptionBootFileURL)
	if err != nil {
		return nil, err
	}

	u := new(URL)
	err = u.UnmarshalBinary(v)
	return u, err
}

// BootFileParam returns the Boot File Parameters Option value, described in
// RFC 5970, Section 3.2.
//
// The Data structure returned contains any parameters needed for a boot
// file, such as a root filesystem label or a path to a configuration file for
// further chainloading.
func (o Options) BootFileParam() (BootFileParam, error) {
	v, err := o.GetOne(OptionBootFileParam)
	if err != nil {
		return nil, err
	}

	var bfp BootFileParam
	err = bfp.UnmarshalBinary(v)
	return bfp, err
}

// ClientArchType returns the Client System Architecture Type Option value,
// described in RFC 5970, Section 3.3.
//
// The ArchTypes slice returned contains a list of one or more ArchType values.
// The first ArchType listed is the client's most preferable value.
func (o Options) ClientArchType() (ArchTypes, error) {
	v, err := o.GetOne(OptionClientArchType)
	if err != nil {
		return nil, err
	}

	var a ArchTypes
	err = a.UnmarshalBinary(v)
	return a, err
}

// NII returns the Client Network Interface Identifier Option value, described
// in RFC 5970, Section 3.4.
//
// The NII value returned indicates a client's level of Universal Network
// Device Interface (UNDI) support.
func (o Options) NII() (*NII, error) {
	v, err := o.GetOne(OptionNII)
	if err != nil {
		return nil, err
	}

	n := new(NII)
	err = n.UnmarshalBinary(v)
	return n, err
}

// byOptionCode implements sort.Interface for optslice.
type byOptionCode optslice

func (b byOptionCode) Len() int               { return len(b) }
func (b byOptionCode) Less(i int, j int) bool { return b[i].Code < b[j].Code }
func (b byOptionCode) Swap(i int, j int)      { b[i], b[j] = b[j], b[i] }

// enumerate returns an ordered slice of option data from the Options map,
// for use with sending responses to clients.
func (o Options) enumerate() optslice {
	// Send all values for a given key
	var options optslice
	for k, v := range o {
		for _, vv := range v {
			options = append(options, option{
				Code: k,
				Data: vv,
			})
		}
	}

	sort.Sort(byOptionCode(options))
	return options
}

// parseOptions returns a slice of option code and values from an input byte
// slice.  It is used with various different types to enable parsing of both
// top-level options, and options embedded within other options.  If options
// data is malformed, it returns errInvalidOptions.
func parseOptions(b []byte) (Options, error) {
	var length int
	options := make(Options)

	buf := bytes.NewBuffer(b)

	for buf.Len() > 3 {
		// 2 bytes: option code
		o := option{}
		o.Code = OptionCode(binary.BigEndian.Uint16(buf.Next(2)))

		// 2 bytes: option length
		length = int(binary.BigEndian.Uint16(buf.Next(2)))

		// If length indicated is zero, skip to next iteration
		if length == 0 {
			continue
		}

		// N bytes: option data
		o.Data = buf.Next(length)
		// Set slice's max for option's data
		o.Data = o.Data[:len(o.Data):len(o.Data)]

		// If option data has less bytes than indicated by length,
		// return an error
		if len(o.Data) < length {
			return nil, errInvalidOptions
		}

		options.addRaw(o.Code, o.Data)
	}

	// Report error for any trailing bytes
	if buf.Len() != 0 {
		return nil, errInvalidOptions
	}

	return options, nil
}

// option represents an individual DHCP Option, as defined in RFC 3315, Section
// 22. An Option carries both an OptionCode and its raw Data.  The format of
// option data varies depending on the option code.
type option struct {
	Code OptionCode
	Data []byte
}

// optslice is a slice of option values, and is used to help marshal option
// values into binary form.
type optslice []option

// count returns the number of bytes that this slice of options will occupy
// when marshaled to binary form.
func (o optslice) count() int {
	var c int
	for _, oo := range o {
		// 2 bytes: option code
		// 2 bytes: option length
		// N bytes: option data
		c += 2 + 2 + len(oo.Data)
	}

	return c
}

// write writes the option slice into the provided buffer.  The caller must
// ensure that a large enough buffer is provided to write to avoid panics.
func (o optslice) write(p []byte) {
	var i int
	for _, oo := range o {
		// 2 bytes: option code
		binary.BigEndian.PutUint16(p[i:i+2], uint16(oo.Code))
		i += 2

		// 2 bytes: option length
		binary.BigEndian.PutUint16(p[i:i+2], uint16(len(oo.Data)))
		i += 2

		// N bytes: option data
		copy(p[i:i+len(oo.Data)], oo.Data)
		i += len(oo.Data)
	}
}
