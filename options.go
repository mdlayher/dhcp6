package dhcp6

import (
	"bytes"
	"encoding"
	"encoding/binary"
	"errors"
	"net"
	"net/url"
	"sort"
	"time"
)

var (
	// errInvalidBootFileParam is returned when OptionBootFileParam contains
	// extra, invalid data.
	errInvalidBootFileParam = errors.New("invalid boot file parameters")

	// errInvalidOptions is returned when invalid options data is encountered
	// during parsing.  The data could report an incorrect length or have
	// trailing bytes which are not part of the option.
	errInvalidOptions = errors.New("invalid options data")

	// errInvalidElapsedTime is returned when a valid duration cannot be parsed
	// from OptionElapsedTime, because too many or too few bytes are present.
	errInvalidElapsedTime = errors.New("invalid option value for OptionElapsedTime")

	// errInvalidOptionRequest is returned when a valid duration cannot be parsed
	// from OptionOptionRequest, because an odd number of bytes are present.
	errInvalidOptionRequest = errors.New("invalid option value for OptionRequestOption")

	// errInvalidPreference is returned when a valid integer cannot be parsed
	// from OptionPreference, because more or less than one byte are present.
	errInvalidPreference = errors.New("invalid option value for OptionPreference")

	// errInvalidRapidCommit is returned when OptionRapidCommit contains any
	// amount of additional data, since it should be completely empty.
	errInvalidRapidCommit = errors.New("invalid option value for OptionRapidCommit")

	// errInvalidUnicast is returned when a valid IPv6 address cannot be
	// parsed from OptionUnicast, because more or less than 16 bytes are present,
	// or the IP address indicated is an IPv4 address.
	errInvalidUnicast = errors.New("invalid option value for OptionUnicast")

	// errInvalidClass is returned when OptionUserClass or OptionVendorClass
	// contain extra, invalid data.
	errInvalidClass = errors.New("invalid option value for OptionUserClass or OptionVendorClass")
)

// Options is a map of OptionCode keys with a slice of byte slice values.
// Its methods can be used to easily check for and parse additional
// information from a client request.  If raw data is needed, the map
// can be accessed directly.
type Options map[OptionCode][][]byte

// Add adds a new OptionCode key and BinaryMarshaler struct's bytes to the
// Options map.
func (o Options) Add(key OptionCode, value encoding.BinaryMarshaler) error {
	b, err := value.MarshalBinary()
	if err != nil {
		return err
	}

	o.AddRaw(key, b)
	return nil
}

// AddRaw adds a new OptionCode key and raw value byte slice to the
// Options map.
func (o Options) AddRaw(key OptionCode, value []byte) {
	o[key] = append(o[key], value)
}

// Get attempts to retrieve the first value specified by an OptionCode
// key.  If a value is found, get returns the value and boolean true.
// If it is not found, Get returns nil and boolean false.
func (o Options) Get(key OptionCode) ([]byte, bool) {
	// Empty map has no key/value pairs
	if len(o) == 0 {
		return nil, false
	}

	// Check for value by key
	v, ok := o[key]
	if !ok {
		return nil, false
	}

	// Some options can actually have zero length (OptionRapidCommit),
	// so just return an empty byte slice if this is the case
	if len(v) == 0 {
		return []byte{}, true
	}

	return v[0], true
}

// ClientID returns the Client Identifier Option value, as described in RFC
// 3315, Section 22.2.
//
// The DUID returned allows unique identification of a client to a server.
//
// The boolean return value indicates if OptionClientID was present in the
// Options map.  The error return value indicates if a known, valid DUID type
// could be parsed from the option.
func (o Options) ClientID() (DUID, bool, error) {
	v, ok := o.Get(OptionClientID)
	if !ok {
		return nil, false, nil
	}

	d, err := parseDUID(v)
	return d, true, err
}

// ServerID returns the Server Identifier Option value, as described in RFC
// 3315, Section 22.3.
//
// The DUID returned allows unique identification of a server to a client.
//
// The boolean return value indicates if OptionServerID was present in the
// Options map.  The error return value indicates if a known, valid DUID type
// could be parsed from the option.
func (o Options) ServerID() (DUID, bool, error) {
	v, ok := o.Get(OptionServerID)
	if !ok {
		return nil, false, nil
	}

	d, err := parseDUID(v)
	return d, true, err
}

// IANA returns the Identity Association for Non-temporary Addresses Option
// value, as described in RFC 3315, Section 22.4.
//
// Multiple IANA values may be present in a single DHCP request.
//
// The boolean return value indicates if OptionIANA was present in the Options
// map.  The error return value indicates if one or more valid IANAs could not
// be parsed from the option.
func (o Options) IANA() ([]*IANA, bool, error) {
	// Client may send multiple IANA option requests, so we must
	// access the map directly
	vv, ok := o[OptionIANA]
	if !ok {
		return nil, false, nil
	}

	// Parse each IA_NA value
	iana := make([]*IANA, len(vv), len(vv))
	for i := range vv {
		ia := new(IANA)
		if err := ia.UnmarshalBinary(vv[i]); err != nil {
			return nil, true, err
		}

		iana[i] = ia
	}

	return iana, true, nil
}

// IATA returns the Identity Association for Temporary Addresses Option
// value, as described in RFC 3315, Section 22.5.
//
// Multiple IATA values may be present in a single DHCP request.
//
// The boolean return value indicates if OptionIATA was present in the Options
// map.  The error return value indicates if one or more valid IATAs could not
// be parsed from the option.
func (o Options) IATA() ([]*IATA, bool, error) {
	// Client may send multiple IATA option requests, so we must
	// access the map directly
	vv, ok := o[OptionIATA]
	if !ok {
		return nil, false, nil
	}

	// Parse each IA_NA value
	iata := make([]*IATA, len(vv), len(vv))
	for i := range vv {
		ia := new(IATA)
		if err := ia.UnmarshalBinary(vv[i]); err != nil {
			return nil, true, err
		}

		iata[i] = ia
	}

	return iata, true, nil
}

// IAAddr returns the Identity Association Address Option value, as described
// in RFC 3315, Section 22.6.
//
// The IAAddr option must always appear encapsulated in the Options map of a
// IANA or IATA option.  Multiple IAAddr values may be
// present in a single DHCP request.
//
// The boolean return value indicates if OptionIAAddr was present in the Options
// map.  The error return value indicates if one or more valid IAAddrs could not
// be parsed from the option.
func (o Options) IAAddr() ([]*IAAddr, bool, error) {
	// Client may send multiple IAAddr option requests, so we must
	// access the map directly
	vv, ok := o[OptionIAAddr]
	if !ok {
		return nil, false, nil
	}

	// Parse each IAAddr value
	iaaddr := make([]*IAAddr, len(vv), len(vv))
	for i := range vv {
		iaa := new(IAAddr)
		if err := iaa.UnmarshalBinary(vv[i]); err != nil {
			return nil, true, err
		}

		iaaddr[i] = iaa
	}

	return iaaddr, true, nil
}

// OptionRequest returns the Option Request Option value, as described in RFC
// 3315, Section 22.7.
//
// The slice of OptionCode values indicates the options a DHCP client is
// interested in receiving from a server.
//
// The boolean return value indicates if OptionORO was present in the Options
// map.  The error return value indicates if a valid OptionCode slice could be
// parsed from the option.
func (o Options) OptionRequest() ([]OptionCode, bool, error) {
	v, ok := o.Get(OptionORO)
	if !ok {
		return nil, false, nil
	}

	// Length must be divisible by 2
	if len(v)%2 != 0 {
		return nil, false, errInvalidOptionRequest
	}

	// Fill slice by parsing every two bytes using index i,
	// and using index j to insert options and track number
	// of iterations until no more options exist
	opts := make([]OptionCode, len(v)/2, len(v)/2)
	for i, j := 0, 0; j < len(v)/2; i, j = i+2, j+1 {
		opts[j] = OptionCode(binary.BigEndian.Uint16(v[i : i+2]))
	}

	return opts, true, nil
}

// Preference returns the Preference Option value, as described in RFC 3315,
// Section 22.8.
//
// The integer preference value is sent by a server to a client to affect the
// selection of a server by the client.
//
// The boolean return value indicates if OptionPreference was present in the
// Options map.  The error return value indicates if a valid integer value
// could not be parsed from the option.
func (o Options) Preference() (uint8, bool, error) {
	v, ok := o.Get(OptionPreference)
	if !ok {
		return 0, false, nil
	}

	// Length must be exactly 1
	if len(v) != 1 {
		return 0, false, errInvalidPreference
	}

	return uint8(v[0]), true, nil
}

// ElapsedTime returns the Elapsed Time Option value, as described in RFC 3315,
// Section 22.9.
//
// The time.Duration returned reports the time elapsed during a DHCP
// transaction, as reported by a client.
//
// The boolean return value indicates if OptionElapsedTime was present in the
// Options map.  The error return value indicates if a valid duration could be
// parsed from the option.
func (o Options) ElapsedTime() (time.Duration, bool, error) {
	v, ok := o.Get(OptionElapsedTime)
	if !ok {
		return 0, false, nil
	}

	// Data must be exactly two bytes
	if len(v) != 2 {
		return 0, false, errInvalidElapsedTime
	}

	// Time is reported in hundredths of seconds, so we convert
	// it to a more manageable milliseconds
	return time.Duration(binary.BigEndian.Uint16(v)) * 10 * time.Millisecond, true, nil
}

// Unicast returns the IP from a Unicast Option value, described in RFC 3315,
// Section 22.12.
//
// The IP return value indicates a server's IPv6 address, which a client may
// use to contact the server via unicast.
//
// The boolean return value indicates if OptionUnicast was present in the
// Options map.  The error return value indicates if a valid IPv6 address
// could not be parsed from the option.
func (o Options) Unicast() (net.IP, bool, error) {
	v, ok := o.Get(OptionUnicast)
	if !ok {
		return nil, false, nil
	}

	// IP must be be exactly 16 bytes
	if len(v) != 16 {
		return nil, false, errInvalidUnicast
	}

	// IP must not be IPv4 address
	ip := net.IP(v)
	if ip.To4() != nil {
		return nil, false, errInvalidUnicast
	}

	return ip, true, nil
}

// StatusCode returns the Status Code Option value, described in RFC 3315,
// Section 22.13.
//
// The StatusCode return value may be used to determine a code and an
// explanation for the status.
//
// The boolean return value indicates if OptionStatusCode was present in the
// Options map.  The error return value indicates if a valid StatusCode could
// not be parsed from the option.
func (o Options) StatusCode() (*StatusCode, bool, error) {
	v, ok := o.Get(OptionStatusCode)
	if !ok {
		return nil, false, nil
	}

	s := new(StatusCode)
	err := s.UnmarshalBinary(v)
	return s, true, err
}

// RapidCommit returns the Rapid Commit Option value, described in RFC 3315,
// Section 22.14.
//
// The boolean return value indicates if OptionRapidCommit was present in the
// Options map, and thus, if Rapid Commit should be used.
//
// The error return value indicates if a valid Rapid Commit Option could not
// be parsed.
func (o Options) RapidCommit() (bool, error) {
	v, ok := o.Get(OptionRapidCommit)
	if !ok {
		return false, nil
	}

	// Data must be completely empty; presence of the Rapid Commit option
	// indicates it is requested.
	if len(v) != 0 {
		return false, errInvalidRapidCommit
	}

	return true, nil
}

// UserClass returns the User Class Option value, described in RFC 3315,
// Section 22.15.
//
// The slice of byte slices returned contains any raw class data present in
// the option.
//
// The boolean return value indicates if OptionUserClass was present in the
// Options map.  The error return value indicates if any errors were present
// in the class data.
func (o Options) UserClass() ([][]byte, bool, error) {
	v, ok := o.Get(OptionUserClass)
	if !ok {
		return nil, false, nil
	}

	c, err := parseClasses(v)
	return c, true, err
}

// VendorClass returns the Vendor Class Option value, described in RFC 3315,
// Section 22.15.
//
// The slice of byte slices returned contains any raw class data present in
// the option.
//
// The boolean return value indicates if OptionVendorClass was present in the
// Options map.  The error return value indicates if any errors were present
// in the class data.
func (o Options) VendorClass() ([][]byte, bool, error) {
	v, ok := o.Get(OptionVendorClass)
	if !ok {
		return nil, false, nil
	}

	c, err := parseClasses(v)
	return c, true, err
}

// IAPD returns the Identity Association for Prefix Delegation Option value,
// described in RFC 3633, Section 9.
//
// Multiple IAPD values may be present in a a single DHCP request.
//
// The boolean return value indicates if OptionIAPD was present in the Options
// map.  The error return value indicates if one or more valid IAPDs could not
// be parsed from the option.
func (o Options) IAPD() ([]*IAPD, bool, error) {
	// Client may send multiple IAPD option requests, so we must
	// access the map directly
	vv, ok := o[OptionIAPD]
	if !ok {
		return nil, false, nil
	}

	// Parse each IA_PD value
	iapd := make([]*IAPD, len(vv))
	for i := range vv {
		ia := new(IAPD)
		if err := ia.UnmarshalBinary(vv[i]); err != nil {
			return nil, true, err
		}

		iapd[i] = ia
	}

	return iapd, true, nil
}

// IAPrefix returns the Identity Association Prefix Option value, as described
// in RFC 3633, Section 10.
//
// Multiple IAPrefix values may be present in a a single DHCP request.
//
// The boolean return value indicates if OptionIAPrefix was present in the
// Options map.  The error return value indicates if one or more valid
// IAPrefixes could not be parsed from the option.
func (o Options) IAPrefix() ([]*IAPrefix, bool, error) {
	// Client may send multiple IAPrefix option requests, so we must
	// access the map directly
	vv, ok := o[OptionIAPrefix]
	if !ok {
		return nil, false, nil
	}

	// Parse each IAPrefix value
	iaprefix := make([]*IAPrefix, len(vv))
	for i := range vv {
		ia := new(IAPrefix)
		if err := ia.UnmarshalBinary(vv[i]); err != nil {
			return nil, true, err
		}

		iaprefix[i] = ia
	}

	return iaprefix, true, nil
}

// BootFileURL returns the Boot File URL Option value, described in RFC 5970,
// Section 3.1.
//
// The URL return value contains a URL which may be used by clients to obtain
// a boot file for PXE.
//
// The boolean return value indicates if OptionBootFileURL was present in the
// Options map.  The error return value indicates if a valid boot file URL
// could not be parsed from the option.
func (o Options) BootFileURL() (*url.URL, bool, error) {
	v, ok := o.Get(OptionBootFileURL)
	if !ok {
		return nil, false, nil
	}

	u, err := url.Parse(string(v))
	return u, true, err
}

// BootFileParam returns the Boot File Parameters Option value, described in
// RFC 5970, Section 3.2.
//
// The slice of strings returned contains any parameters needed for a boot
// file, such as a root filesystem label or a path to a configuration file for
// further chainloading.
//
// The boolean return value indicates if OptionBootFileParam was present in
// the Options map.  The error return value indicates if valid boot file
// parameters could not be parsed from the option.
func (o Options) BootFileParam() ([]string, bool, error) {
	v, ok := o.Get(OptionBootFileParam)
	if !ok {
		return nil, false, nil
	}

	// This data is the same format as user/vendor class data, but returned
	// as a string slice instead.  For now, we will use the same functionality,
	// but this should probably be refactored into something more general in
	// the future.
	bb, err := parseClasses(v)
	if err != nil {
		return nil, true, errInvalidBootFileParam
	}

	ss := make([]string, len(bb))
	for i := range bb {
		ss[i] = string(bb[i])
	}

	return ss, true, nil
}

// parseClasses parses multiple contiguous byte slices contained in
// OptionUserClass or OptionVendorClass, of the form:
//   - 2 bytes: length
//   - N bytes: class data
func parseClasses(v []byte) ([][]byte, error) {
	classes := make([][]byte, 0)
	buf := bytes.NewBuffer(v)

	// Iterate until not enough bytes remain to parse another length value
	for buf.Len() > 1 {
		classes = append(classes, buf.Next(int(binary.BigEndian.Uint16(buf.Next(2)))))
	}

	// At least one instance of class data must be present
	if len(classes) == 0 {
		return nil, errInvalidClass
	}

	// If we encounter any trailing bytes, report an error
	if buf.Len() != 0 {
		return nil, errInvalidClass
	}

	return classes, nil
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

		// If option data has less bytes than indicated by length,
		// return an error
		if len(o.Data) < length {
			return nil, errInvalidOptions
		}

		options.AddRaw(o.Code, o.Data)
	}

	// Report error for any trailing bytes
	if buf.Len() != 0 {
		return nil, errInvalidOptions
	}

	return options, nil
}

// option represents an individual DHCP Option, as defined in RFC 3315,
// Section 22.  An Option carries both an OptionCode and its raw Data.  The
// format of option data varies depending on the option code.
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
