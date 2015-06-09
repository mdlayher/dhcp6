package dhcp6

import (
	"bytes"
	"net"
	"reflect"
	"testing"
	"time"
)

// TestNewDUIDLLT verifies that NewDUIDLLT generates a proper DUIDLLT or error
// from an input hardware type, time value, and hardware address.
func TestNewDUIDLLT(t *testing.T) {
	var tests = []struct {
		description  string
		hardwareType uint16
		time         time.Time
		hardwareAddr net.HardwareAddr
		duid         *DUIDLLT
		err          error
	}{
		{
			description: "date too early",
			time:        duidLLTTime.Add(-1 * time.Minute),
			err:         ErrInvalidDUIDLLTTime,
		},
		{
			description:  "OK",
			hardwareType: 1,
			time:         duidLLTTime.Add(1 * time.Minute),
			hardwareAddr: net.HardwareAddr([]byte{0, 1, 0, 1, 0, 1}),
			duid: &DUIDLLT{
				Type:         DUIDTypeLLT,
				HardwareType: 1,
				Time:         duidLLTTime.Add(1 * time.Minute).Sub(duidLLTTime),
				HardwareAddr: net.HardwareAddr([]byte{0, 1, 0, 1, 0, 1}),
			},
		},
	}

	for i, tt := range tests {
		duid, err := NewDUIDLLT(tt.hardwareType, tt.time, tt.hardwareAddr)
		if err != nil {
			if want, got := tt.err, err; want != got {
				t.Fatalf("[%02d] test %q, unexpected error: %v != %v",
					i, tt.description, want, got)
			}

			continue
		}

		if want, got := tt.duid, duid; !reflect.DeepEqual(want, got) {
			t.Fatalf("[%02d] test %q, unexpected DUIDLLT:\n- want %v\n-  got %v",
				i, tt.description, want, got)
		}
	}
}

// TestNewDUIDEN verifies that NewDUIDEN generates a proper DUIDEN from
// an input enterprise number and identifier.
func TestNewDUIDEN(t *testing.T) {
	var tests = []struct {
		enterpriseNumber uint32
		identifier       []byte
		duid             *DUIDEN
	}{
		{
			enterpriseNumber: 100,
			identifier:       []byte{0, 1, 2, 3, 4},
			duid: &DUIDEN{
				Type:             DUIDTypeEN,
				EnterpriseNumber: 100,
				Identifier:       []byte{0, 1, 2, 3, 4},
			},
		},
	}

	for i, tt := range tests {
		if want, got := tt.duid, NewDUIDEN(tt.enterpriseNumber, tt.identifier); !reflect.DeepEqual(want, got) {
			t.Fatalf("[%02d] unexpected DUIDEN:\n- want %v\n-  got %v", i, want, got)
		}
	}
}

// TestNewDUIDLL verifies that NewDUIDLL generates a proper DUIDLL from
// an input hardware type and hardware address.
func TestNewDUIDLL(t *testing.T) {
	var tests = []struct {
		hardwareType uint16
		hardwareAddr net.HardwareAddr
		duid         *DUIDLL
	}{
		{
			hardwareType: 1,
			hardwareAddr: net.HardwareAddr([]byte{0, 0, 0, 0, 0, 0}),
			duid: &DUIDLL{
				Type:         DUIDTypeLL,
				HardwareType: 1,
				HardwareAddr: net.HardwareAddr([]byte{0, 0, 0, 0, 0, 0}),
			},
		},
	}

	for i, tt := range tests {
		if want, got := tt.duid, NewDUIDLL(tt.hardwareType, tt.hardwareAddr); !reflect.DeepEqual(want, got) {
			t.Fatalf("[%02d] unexpected DUIDLL:\n- want %v\n-  got %v", i, want, got)
		}
	}
}

// Test_parseDUID verifies that parseDUID detects the correct DUID type for a
// variety of input data.
func Test_parseDUID(t *testing.T) {
	var tests = []struct {
		buf    []byte
		result reflect.Type
		err    error
	}{
		{
			buf: []byte{0},
			err: errInvalidDUID,
		},
		{
			buf: []byte{0, 0},
			err: errUnknownDUID,
		},
		// Known types padded out to be just long enough to not error
		{
			buf:    []byte{0, 1, 0, 0, 0, 0, 0, 0},
			result: reflect.TypeOf(&DUIDLLT{}),
		},
		{
			buf:    []byte{0, 2, 0, 0, 0, 0},
			result: reflect.TypeOf(&DUIDEN{}),
		},
		{
			buf:    []byte{0, 3, 0, 0},
			result: reflect.TypeOf(&DUIDLL{}),
		},
		{
			buf: []byte{0, 4},
			err: errUnknownDUID,
		},
	}

	for i, tt := range tests {
		d, err := parseDUID(tt.buf)
		if err != nil {
			if want, got := tt.err, err; want != got {
				t.Fatalf("[%02d] unexpected error for parseDUID(%v): %v != %v",
					i, tt.buf, want, got)
			}

			continue
		}

		if want, got := tt.result, reflect.TypeOf(d); want != got {
			t.Fatalf("[%02d] unexpected type for parseDUID(%v): %v != %v",
				i, tt.buf, want, got)
		}
	}
}

// Test_parseDUIDLLT verifies that parseDUIDLLT returns appropriate DUIDLLTs and
// errors for various input byte slices.
func Test_parseDUIDLLT(t *testing.T) {
	var tests = []struct {
		description string
		buf         []byte
		duid        *DUIDLLT
		err         error
	}{
		{
			description: "nil buffer, invalid DUID-LLT",
			err:         errInvalidDUIDLLT,
		},
		{
			description: "empty buffer, invalid DUID-LLT",
			buf:         []byte{},
			err:         errInvalidDUIDLLT,
		},
		{
			description: "length 7 buffer, invalid DUID-LLT",
			buf:         bytes.Repeat([]byte{0}, 7),
			err:         errInvalidDUIDLLT,
		},
		{
			description: "wrong DUID type",
			buf: []byte{
				0, 2,
				0, 0,
				0, 0, 0, 0,
				0, 0, 0, 0, 0, 0,
			},
			err: errInvalidDUIDLLT,
		},
		{
			description: "OK DUIDLLT",
			buf: []byte{
				0, 1,
				0, 1,
				0, 0, 0, 60,
				0, 1, 0, 1, 0, 1,
			},
			duid: &DUIDLLT{
				Type:         DUIDTypeLLT,
				HardwareType: 1,
				Time:         1 * time.Minute,
				HardwareAddr: []byte{0, 1, 0, 1, 0, 1},
			},
		},
	}

	for i, tt := range tests {
		duid, err := parseDUIDLLT(tt.buf)
		if err != nil {
			if want, got := tt.err, err; want != got {
				t.Fatalf("[%02d] test %q, unexpected error: %v != %v",
					i, tt.description, want, got)
			}

			continue
		}

		if want, got := tt.duid, duid; !reflect.DeepEqual(want, got) {
			t.Fatalf("[%02d] test %q, unexpected DUID-LLT:\n- want: %v\n-  got: %v",
				i, tt.description, want, got)
		}
	}
}

// Test_parseDUIDEN verifies that parseDUIDEN returns appropriate DUIDENs and
// errors for various input byte slices.
func Test_parseDUIDEN(t *testing.T) {
	var tests = []struct {
		description string
		buf         []byte
		duid        *DUIDEN
		err         error
	}{
		{
			description: "nil buffer, invalid DUID-EN",
			err:         errInvalidDUIDEN,
		},
		{
			description: "empty buffer, invalid DUID-EN",
			buf:         []byte{},
			err:         errInvalidDUIDEN,
		},
		{
			description: "length 5 buffer, invalid DUID-EN",
			buf:         bytes.Repeat([]byte{0}, 5),
			err:         errInvalidDUIDEN,
		},
		{
			description: "wrong DUID type",
			buf: []byte{
				0, 3,
				0, 0, 0, 0,
			},
			err: errInvalidDUIDEN,
		},
		{
			description: "OK DUIDEN",
			buf: []byte{
				0, 2,
				0, 0, 0, 100,
				0, 1, 2, 3, 4, 5,
			},
			duid: &DUIDEN{
				Type:             DUIDTypeEN,
				EnterpriseNumber: 100,
				Identifier:       []byte{0, 1, 2, 3, 4, 5},
			},
		},
	}

	for i, tt := range tests {
		duid, err := parseDUIDEN(tt.buf)
		if err != nil {
			if want, got := tt.err, err; want != got {
				t.Fatalf("[%02d] test %q, unexpected error: %v != %v",
					i, tt.description, want, got)
			}

			continue
		}

		if want, got := tt.duid, duid; !reflect.DeepEqual(want, got) {
			t.Fatalf("[%02d] test %q, unexpected DUID-EN:\n- want: %v\n-  got: %v",
				i, tt.description, want, got)
		}
	}
}

// Test_parseDUIDLL verifies that parseDUIDLL returns appropriate DUIDLLs and
// errors for various input byte slices.
func Test_parseDUIDLL(t *testing.T) {
	var tests = []struct {
		description string
		buf         []byte
		duid        *DUIDLL
		err         error
	}{
		{
			description: "nil buffer, invalid DUID-LL",
			err:         errInvalidDUIDLL,
		},
		{
			description: "empty buffer, invalid DUID-LL",
			buf:         []byte{},
			err:         errInvalidDUIDLL,
		},
		{
			description: "length 7 buffer, invalid DUID-LL",
			buf:         bytes.Repeat([]byte{0}, 7),
			err:         errInvalidDUIDLL,
		},
		{
			description: "wrong DUID type",
			buf: []byte{
				0, 1,
				0, 0,
				0, 0, 0, 0,
				0, 0, 0, 0, 0, 0,
			},
			err: errInvalidDUIDLL,
		},
		{
			description: "OK DUIDLL",
			buf: []byte{
				0, 3,
				0, 1,
				0, 1, 0, 1, 0, 1,
			},
			duid: &DUIDLL{
				Type:         DUIDTypeLL,
				HardwareType: 1,
				HardwareAddr: []byte{0, 1, 0, 1, 0, 1},
			},
		},
	}

	for i, tt := range tests {
		duid, err := parseDUIDLL(tt.buf)
		if err != nil {
			if want, got := tt.err, err; want != got {
				t.Fatalf("[%02d] test %q, unexpected error: %v != %v",
					i, tt.description, want, got)
			}

			continue
		}

		if want, got := tt.duid, duid; !reflect.DeepEqual(want, got) {
			t.Fatalf("[%02d] test %q, unexpected DUID-LL:\n- want: %v\n-  got: %v",
				i, tt.description, want, got)
		}
	}
}
