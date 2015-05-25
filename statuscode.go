package dhcp6

import (
	"encoding/binary"
	"errors"
)

var (
	// errInvalidStatusCode is returned when a byte slice does not contain
	// enough bytes to parse a valid StatusCode value.
	errInvalidStatusCode = errors.New("not enough bytes for valid StatusCode")
)

// StatusCode represents a Status Code, as defined in RFC 3315, Section 5.4.
// DHCP clients and servers can use status codes to communicate successes
// or failures, and provide additional information using a message to describe
// specific failures.
type StatusCode []byte

// NewStatusCode creates a new StatusCode from an input Status value and a
// string message.
func NewStatusCode(code Status, message string) StatusCode {
	msg := []byte(message)
	status := make(StatusCode, 2+len(msg), 2+len(msg))

	binary.BigEndian.PutUint16(status[0:2], uint16(code))
	copy(status[2:], msg)

	return status
}

// Bytes returns the underlying byte slice for a StatusCode.
func (s StatusCode) Bytes() []byte {
	return []byte(s)
}

// Code returns the Status value stored within this StatusCode.
func (s StatusCode) Code() Status {
	// Too short to contain Status
	if len(s) < 2 {
		return Status(-1)
	}

	return Status(binary.BigEndian.Uint16(s[0:2]))
}

// Message returns a string message containing more information regarding
// successes or failures.
func (s StatusCode) Message() string {
	return string(s[2:])
}

// parseStatusCode attempts to parse an input byte slice as a StatusCode.
func parseStatusCode(s []byte) (StatusCode, error) {
	if len(s) < 2 {
		return nil, errInvalidStatusCode
	}

	return StatusCode(s), nil
}
