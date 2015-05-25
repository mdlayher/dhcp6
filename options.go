package dhcp6

import (
	"bytes"
	"encoding/binary"
	"errors"
	"sort"
	"time"
)

var (
	// errInvalidElapsedTime is returned when a valid duration cannot be parsed
	// from OptionElapsedTime, because too many or too few bytes are present.
	errInvalidElapsedTime = errors.New("invalid option value for OptionElapsedTime")

	// errInvalidOptionRequest is returned when a valid duration cannot be parsed
	// from OptionOptionRequest, because an odd number of bytes are present.
	errInvalidOptionRequest = errors.New("invalid option value for OptionRequestOption")

	// errInvalidPreference is returned when a valid integer cannot be parsed
	// from OptionPreference, because more or less than one byte are present.
	errInvalidPreference = errors.New("invalid option value for OptionPreference")
)

// Options is a map of OptionCode keys with a slice of byte slice values.
// Its methods can be used to easily check for and parse additional
// information from a client request.  If raw data is needed, the map
// can be accessed directly.
type Options map[OptionCode][][]byte

// Add adds a new OptionCode key and Byteser struct's bytes to the
// Options map.
func (o Options) Add(key OptionCode, value Byteser) {
	o.AddRaw(key, value.Bytes())
}

// AddRaw adds a new OptionCode key and raw value byte slice to the
// Options map.
func (o Options) AddRaw(key OptionCode, value []byte) {
	o[key] = append(o[key], value)
}

// Get attempts to retrieve the first value specified by an OptionCode
// key.  If a value is found, get returns the value and boolean true.
// If it is not found, or the value slice is entirely empty, Get
// returns nil and boolean false.
func (o Options) Get(key OptionCode) ([]byte, bool) {
	// Empty map has no key/value pairs
	if len(o) == 0 {
		return nil, false
	}

	// Check for value by key
	v, ok := o[key]
	if !ok || len(v) == 0 {
		return nil, false
	}

	return v[0], true
}

// ClientID returns the Client Identifier Option value, described in RFC 3315,
// Section 22.2.  The DUID returned allows unique identification of a client
// to a server.  The boolean return value indicates if OptionClientID was
// present in the Options map.  The error return value indicates if a known,
// valid DUID type could be parsed from the option.
func (o Options) ClientID() (DUID, bool, error) {
	v, ok := o.Get(OptionClientID)
	if !ok {
		return nil, false, nil
	}

	d, err := parseDUID(v)
	return d, true, err
}

// ServerID returns the Server Identifier Option value, described in RFC 3315,
// Section 22.3.  The DUID returned allows unique identification of a server
// to a client.  The boolean return value indicates if OptionServerID was
// present in the Options map.  The error return value indicates if a known,
// valid DUID type could be parsed from the option.
func (o Options) ServerID() (DUID, bool, error) {
	v, ok := o.Get(OptionServerID)
	if !ok {
		return nil, false, nil
	}

	d, err := parseDUID(v)
	return d, true, err
}

// IANA returns the Identity Association for Non-temporary Address Option
// value, described in RFC 3315, Section 22.4.  Multiple IANA values may
// be present in a single DHCP request.  The boolean return value indicates if
// OptionIANA was present in the Options map.  The error return value
// indicates if one or more valid IANAs could not be parsed from the option.
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
		ia, err := parseIANA(vv[i])
		if err != nil {
			return nil, true, err
		}

		iana[i] = ia
	}

	return iana, true, nil
}

// IAAddr returns the Identity Association Address Option value, described in
// RFC 3315, Section 22.6.  The IAAddr option must always appear enscapsulated
// in the Options map of a IANA or IATA option.  Multiple IAAddr values may be
// present in a single DHCP request.  The boolean return value indicates if
// OptionIAAddr was present in the Options map.  The error return value
// indicates if one or more valid IAAddrs could be be parsed from the option.
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
		iaa, err := parseIAAddr(vv[i])
		if err != nil {
			return nil, true, err
		}

		iaaddr[i] = iaa
	}

	return iaaddr, true, nil
}

// OptionRequest returns the Option Request Option value, described in RFC 3315,
// Section 22.7.  The slice of OptionCode values indicates the options a DHCP
// client is interested in receiving from a server.  The boolean return value
// indicates if OptionORO was present in the Options map.  The error return
// value indicates if a valid OptionCode slice could be parsed from the option.
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

// Preference returns the Preference Option value, described in RFC 3315,
// Section 22.8.  The integer value is sent by a server to a client to
// affect the selection of a server by the client.  The boolean return value
// indicates if OptionPreference was present in the Options map.  The error
// return value indicates if a valid integer value could not be parsed from
// the option.
func (o Options) Preference() (int, bool, error) {
	v, ok := o.Get(OptionPreference)
	if !ok {
		return 0, false, nil
	}

	// Length must be exactly 1
	if len(v) != 1 {
		return 0, false, errInvalidPreference
	}

	return int(v[0]), true, nil
}

// ElapsedTime returns the Elapsed Time Option value, described in RFC 3315,
// Section 22.9.  The time.Duration returned reports the time elapsed during
// a DHCP transaction, as reported by a client.  The boolean return value
// indicates if OptionElapsedTime was present in the Options map.  The error
// return value indicates if a valid duration could be parsed from the option.
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
// top-level options, and options embedded within other options.
func parseOptions(b []byte) Options {
	var length int
	options := make(Options)

	buf := bytes.NewBuffer(b)

	for buf.Len() > 4 {
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
		// discard the option
		if len(o.Data) < length {
			continue
		}

		options.AddRaw(o.Code, o.Data)
	}

	return options
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
