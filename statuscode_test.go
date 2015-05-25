package dhcp6

import (
	"bytes"
	"testing"
)

// TestNewStatusCode verifies that NewStatusCode creates a proper StatusCode
// value for the input values.
func TestNewStatusCode(t *testing.T) {
	var tests = []struct {
		status  Status
		message string
		sc      StatusCode
	}{
		{
			status:  StatusSuccess,
			message: "Success",
			sc:      StatusCode(append([]byte{0, 0}, []byte("Success")...)),
		},
		{
			status:  StatusUnspecFail,
			message: "Failure",
			sc:      StatusCode(append([]byte{0, 1}, []byte("Failure")...)),
		},
		{
			status:  StatusNoAddrsAvail,
			message: "No addresses available",
			sc:      StatusCode(append([]byte{0, 2}, []byte("No addresses available")...)),
		},
	}

	for i, tt := range tests {
		if want, got := tt.sc, NewStatusCode(tt.status, tt.message); !bytes.Equal(want, got) {
			t.Fatalf("[%02d] unexpected StatusCode for NewStatusCode(%v, %q)\n- want: %v\n-  got: %v",
				i, tt.status, tt.message, want, got)
		}
	}
}

// TestStatusCodeCode verifies that StatusCode.Code produces a correct
// string value for an input buffer.
func TestStatusCodeCode(t *testing.T) {
	var tests = []struct {
		buf  []byte
		code Status
	}{
		{
			buf:  nil,
			code: Status(-1),
		},
		{
			buf:  []byte{},
			code: Status(-1),
		},
		{
			buf:  []byte{0},
			code: Status(-1),
		},
		{
			buf:  []byte{0, 0},
			code: StatusSuccess,
		},
	}

	for i, tt := range tests {
		if want, got := tt.code, StatusCode(tt.buf).Code(); want != got {
			t.Fatalf("[%02d] unexpected StatusCode(%v).Code(): %v != %v",
				i, tt.buf, want, got)
		}
	}
}

// TestStatusCodeMessage verifies that StatusCode.Message produces a correct
// string value for an input buffer.
func TestStatusCodeMessage(t *testing.T) {
	var tests = []struct {
		buf     []byte
		message string
	}{
		{
			buf:     nil,
			message: "",
		},
		{
			buf:     []byte{},
			message: "",
		},
		{
			buf:     []byte("hello"),
			message: "hello",
		},
	}

	// Prepend empty code
	for i, tt := range tests {
		if want, got := tt.message, StatusCode(append([]byte{0, 0}, tt.buf...)).Message(); want != got {
			t.Fatalf("[%02d] unexpected StatusCode(%v).Message():\n- want: %q\n-  got: %q",
				i, tt.buf, want, got)
		}
	}
}

// Test_parseStatusCode verifies that parseStatusCode returns correct StatusCode
// and error values for several input values.
func Test_parseStatusCode(t *testing.T) {
	var tests = []struct {
		buf []byte
		sc  StatusCode
		err error
	}{
		{
			buf: []byte{0},
			err: errInvalidStatusCode,
		},
		{
			buf: []byte{0, 0},
			sc:  StatusCode([]byte{0, 0}),
		},
		{
			buf: append([]byte{0, 1}, []byte("deadbeef")...),
			sc:  StatusCode(append([]byte{0, 1}, []byte("deadbeef")...)),
		},
	}

	for i, tt := range tests {
		sc, err := parseStatusCode(tt.buf)
		if err != nil {
			if want, got := tt.err, err; want != got {
				t.Fatalf("[%02d] unexpected error for parseStatusCode(%v): %v != %v",
					i, tt.buf, want, got)
			}

			continue
		}

		if want, got := tt.sc.Bytes(), sc.Bytes(); !bytes.Equal(want, got) {
			t.Fatalf("[%02d] unexpected StatusCode for parseStatusCode(%v)\n- want: %v\n-  got: %v",
				i, tt.buf, want, got)
		}
	}
}
