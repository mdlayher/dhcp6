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
)

// Options is a map of OptionCode keys with a slice of byte slice values.
// Its methods can be used to easily check for and parse additional
// information from a client request.  If raw data is needed, the map
// can be accessed directly.
type Options map[OptionCode][][]byte

// Add adds a new OptionCode key and value byte slice to the Options map.
func (o Options) Add(key OptionCode, value []byte) {
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

// byOptionCode implements sort.Interface for []option.
type byOptionCode []option

func (b byOptionCode) Len() int               { return len(b) }
func (b byOptionCode) Less(i int, j int) bool { return b[i].Code < b[j].Code }
func (b byOptionCode) Swap(i int, j int)      { b[i], b[j] = b[j], b[i] }

// enumerate returns an ordered slice of option data from the Options map,
// for use with sending responses to clients.
func (o Options) enumerate() []option {
	options := make([]option, 0)

	// Send all values for a given key
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
func parseOptions(b []byte) []option {
	var length int
	var options []option

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

		options = append(options, o)
	}

	return options
}
