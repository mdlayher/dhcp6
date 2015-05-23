package dhcp6

import (
	"encoding/binary"
	"time"
)

// Options is a map of OptionCode keys with a slice of byte slice values.
// Its methods can be used to easily check for and parse additional
// information from a client request.  If raw data is needed, the map
// can be accessed directly.
type Options map[OptionCode][][]byte

// add adds a new OptionCode key and value byte slice to the Options map.
func (o Options) add(key OptionCode, value []byte) {
	o[key] = append(o[key], value)
}

// get attempts to retrieve the first value specified by an OptionCode
// key.  If a value is found, get returns the value and boolean true.
// If it is not found, get returns nil and boolean false.
func (o Options) get(key OptionCode) ([]byte, bool) {
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
// present in the Options map.
func (o Options) ClientID() (DUID, bool) {
	v, ok := o.get(OptionClientID)
	if !ok {
		return nil, false
	}

	return parseDUID(v), true
}

// ServerID returns the Server Identifier Option value, described in RFC 3315,
// Section 22.3.  The DUID returned allows unique identification of a server
// to a client.  The boolean return value indicates if OptionServerID was
// present in the Options map.
func (o Options) ServerID() (DUID, bool) {
	v, ok := o.get(OptionServerID)
	if !ok {
		return nil, false
	}

	return parseDUID(v), true
}

// ElapsedTime returns the Elapsed Time Option value, described in RFC 3315,
// Section 22.9.  The time.Duration returned reports the time elapsed during
// a DHCP transaction, as reported by a client.  The boolean return value
// indicates if OptionElapsedTime was present in the Options map.
func (o Options) ElapsedTime() (time.Duration, bool) {
	v, ok := o.get(OptionElapsedTime)
	if !ok {
		return 0, false
	}

	// Time is reported in hundredths of seconds, so we convert
	// it to a more manageable milliseconds
	return time.Duration(binary.BigEndian.Uint16(v)) * 10 * time.Millisecond, true
}
