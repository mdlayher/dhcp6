package dhcp6

import (
	"bytes"
	"net"
	"reflect"
	"testing"
	"time"
)

// TestDUIDLLT verifies that a DUIDLLT can be properly created from raw DUID
// data, and that each of its fields can be correctly parsed.
func TestDUIDLLT(t *testing.T) {
	var tests = []struct {
		description  string
		buf          []byte
		hardwareType []byte
		time         time.Duration
		hardwareAddr net.HardwareAddr
	}{
		{
			description: "zero hardware type, time, and hardware address",
			buf: []byte{
				0, 1,
				0, 0,
				0, 0, 0, 0,
				0, 0, 0, 0, 0, 0,
			},
			hardwareType: []byte{0, 0},
			time:         0 * time.Second,
			hardwareAddr: net.HardwareAddr([]byte{0, 0, 0, 0, 0, 0}),
		},
		{
			description: "non-zero hardware type, zero time and hardware address",
			buf: []byte{
				0, 1,
				10, 11,
				0, 0, 0, 0,
				0, 0, 0, 0, 0, 0,
			},
			hardwareType: []byte{10, 11},
			time:         0 * time.Second,
			hardwareAddr: net.HardwareAddr([]byte{0, 0, 0, 0, 0, 0}),
		},
		{
			description: "non-zero time, zero hardware type and hardware address",
			buf: []byte{
				0, 1,
				0, 0,
				0, 0, 1, 1,
				0, 0, 0, 0, 0, 0,
			},
			hardwareType: []byte{0, 0},
			time:         (4 * time.Minute) + 17*time.Second,
			hardwareAddr: net.HardwareAddr([]byte{0, 0, 0, 0, 0, 0}),
		},
		{
			description: "non-zero hardware address, zero hardware type and time",
			buf: []byte{
				0, 1,
				0, 0,
				0, 0, 0, 0,
				222, 173, 190, 239, 222, 173,
			},
			hardwareType: []byte{0, 0},
			time:         0 * time.Second,
			hardwareAddr: net.HardwareAddr([]byte{222, 173, 190, 239, 222, 173}),
		},
		{
			description: "non-zero hardware type, time, and hardware address",
			buf: []byte{
				0, 1,
				13, 14,
				0, 0, 2, 1,
				190, 239, 222, 173, 190, 239,
			},
			hardwareType: []byte{13, 14},
			time:         (8 * time.Minute) + 33*time.Second,
			hardwareAddr: net.HardwareAddr([]byte{190, 239, 222, 173, 190, 239}),
		},
	}

	for i, tt := range tests {
		duid := DUIDLLT(tt.buf)
		if want, got := DUIDTypeLLT, duid.Type(); want != got {
			t.Fatalf("[%02d] test %q, unexpected DUIDLLT.Type():\n- test: want %v, got %v",
				i, tt.description, want, got)
		}

		if want, got := tt.hardwareType, duid.HardwareType(); !bytes.Equal(want, got) {
			t.Fatalf("[%02d] test %q, unexpected DUIDLLT.HardwareType():\n- buffer: %v\n- test: want %v, got %v",
				i, tt.description, tt.buf, want, got)
		}

		if want, got := tt.time, duid.Time(); want != got {
			t.Fatalf("[%02d] test %q, unexpected DUIDLLT.Time():\n- buffer: %v\n- test: want %v, got %v",
				i, tt.description, tt.buf, want, got)
		}

		if want, got := tt.hardwareAddr, duid.HardwareAddr(); !bytes.Equal(want, got) {
			t.Fatalf("[%02d] test %q, unexpected DUIDLLT.HardwareAddr():\n- buffer: %v\n- test: want %v, got %v",
				i, tt.description, tt.buf, want, got)
		}

		if want, got := tt.buf, duid.Bytes(); !bytes.Equal(want, got) {
			t.Fatalf("[%02d] test %q, unexpected DUIDLLT.Bytes():\n- want %v\n-  got %v",
				i, tt.description, want, got)
		}
	}
}

// TestDUIDEN verifies that a DUIDEN can be properly created from raw DUID
// data, and that each of its fields can be correctly parsed.
func TestDUIDEN(t *testing.T) {
	var tests = []struct {
		description      string
		buf              []byte
		enterpriseNumber int
		identifier       []byte
	}{
		{
			description: "zero enterprise number and identifier",
			buf: []byte{
				0, 2,
				0, 0, 0, 0,
				0, 0, 0, 0, 0, 0, 0, 0,
			},
			enterpriseNumber: 0,
			identifier:       []byte{0, 0, 0, 0, 0, 0, 0, 0},
		},
		{
			description: "non-zero enterprise number, zero identifier",
			buf: []byte{
				0, 2,
				0, 0, 10, 11,
				0, 0, 0, 0, 0, 0, 0, 0,
			},
			enterpriseNumber: 2571,
			identifier:       []byte{0, 0, 0, 0, 0, 0, 0, 0},
		},
		{
			description: "non-zero identifer, zero enterprise number",
			buf: []byte{
				0, 2,
				0, 0, 0, 0,
				10, 11, 12, 13, 14, 15, 1, 2,
			},
			enterpriseNumber: 0,
			identifier:       []byte{10, 11, 12, 13, 14, 15, 1, 2},
		},
		{
			// Example from: https://tools.ietf.org/html/rfc3315#section-9.3
			description: "non-zero enterprise number and identifier",
			buf: []byte{
				0, 2,
				0, 0, 0, 9,
				12, 192, 132, 221, 3, 0, 9, 18,
			},
			enterpriseNumber: 9,
			identifier:       []byte{12, 192, 132, 221, 3, 0, 9, 18},
		},
	}

	for i, tt := range tests {
		duid := DUIDEN(tt.buf)
		if want, got := DUIDTypeEN, duid.Type(); want != got {
			t.Fatalf("[%02d] test %q, unexpected DUIDEN.Type():\n- test: want %v, got %v",
				i, tt.description, want, got)
		}

		if want, got := tt.enterpriseNumber, duid.EnterpriseNumber(); want != got {
			t.Fatalf("[%02d] test %q, unexpected DUIDEN.EnterpriseNumber():\n- buffer: %v\n- test: want %v, got %v",
				i, tt.description, tt.buf, want, got)
		}

		if want, got := tt.identifier, duid.Identifier(); !bytes.Equal(want, got) {
			t.Fatalf("[%02d] test %q, unexpected DUIDEN.Identifier():\n- buffer: %v\n- test: want %v, got %v",
				i, tt.description, tt.buf, want, got)
		}

		if want, got := tt.buf, duid.Bytes(); !bytes.Equal(want, got) {
			t.Fatalf("[%02d] test %q, unexpected DUIDEN.Bytes():\n- want %v\n-  got %v",
				i, tt.description, want, got)
		}
	}
}

// TestDUIDLL verifies that a DUIDLL can be properly created from raw DUID
// data, and that each of its fields can be correctly parsed.
func TestDUIDLL(t *testing.T) {
	var tests = []struct {
		description  string
		buf          []byte
		hardwareType []byte
		hardwareAddr net.HardwareAddr
	}{
		{
			description: "zero hardware type and hardware address",
			buf: []byte{
				0, 3,
				0, 0,
				0, 0, 0, 0, 0, 0,
			},
			hardwareType: []byte{0, 0},
			hardwareAddr: net.HardwareAddr([]byte{0, 0, 0, 0, 0, 0}),
		},
		{
			description: "non-zero hardware type, zero hardware address",
			buf: []byte{
				0, 3,
				10, 11,
				0, 0, 0, 0, 0, 0,
			},
			hardwareType: []byte{10, 11},
			hardwareAddr: net.HardwareAddr([]byte{0, 0, 0, 0, 0, 0}),
		},
		{
			description: "non-zero hardware address, zero hardware type",
			buf: []byte{
				0, 3,
				0, 0,
				222, 173, 190, 239, 222, 173,
			},
			hardwareType: []byte{0, 0},
			hardwareAddr: net.HardwareAddr([]byte{222, 173, 190, 239, 222, 173}),
		},
		{
			description: "non-zero hardware type and hardware address",
			buf: []byte{
				0, 3,
				13, 14,
				190, 239, 222, 173, 190, 239,
			},
			hardwareType: []byte{13, 14},
			hardwareAddr: net.HardwareAddr([]byte{190, 239, 222, 173, 190, 239}),
		},
	}

	for i, tt := range tests {
		duid := DUIDLL(tt.buf)
		if want, got := DUIDTypeLL, duid.Type(); want != got {
			t.Fatalf("[%02d] test %q, unexpected DUIDLL.Type():\n- test: want %v, got %v",
				i, tt.description, want, got)
		}

		if want, got := tt.hardwareType, duid.HardwareType(); !bytes.Equal(want, got) {
			t.Fatalf("[%02d] test %q, unexpected DUIDLL.HardwareType():\n- buffer: %v\n- test: want %v, got %v",
				i, tt.description, tt.buf, want, got)
		}

		if want, got := tt.hardwareAddr, duid.HardwareAddr(); !bytes.Equal(want, got) {
			t.Fatalf("[%02d] test %q, unexpected DUIDLL.HardwareAddr():\n- buffer: %v\n- test: want %v, got %v",
				i, tt.description, tt.buf, want, got)
		}

		if want, got := tt.buf, duid.Bytes(); !bytes.Equal(want, got) {
			t.Fatalf("[%02d] test %q, unexpected DUIDLL.Bytes():\n- want %v\n-  got %v",
				i, tt.description, want, got)
		}
	}
}

// Test_parseDUID verifies that parseDUID detects the correct DUID type for a
// variety of input data.
func Test_parseDUID(t *testing.T) {
	var tests = []struct {
		buf    []byte
		result reflect.Type
	}{
		{
			buf:    []byte{0, 0},
			result: nil,
		},
		{
			buf:    []byte{0, 1},
			result: reflect.TypeOf(DUIDLLT{}),
		},
		{
			buf:    []byte{0, 2},
			result: reflect.TypeOf(DUIDEN{}),
		},
		{
			buf:    []byte{0, 3},
			result: reflect.TypeOf(DUIDLL{}),
		},
		{
			buf:    []byte{0, 4},
			result: nil,
		},
	}

	for i, tt := range tests {
		if want, got := tt.result, reflect.TypeOf(parseDUID(tt.buf)); want != got {
			t.Fatalf("[%02d] unexpected type for parseDUID(%v):\n- test: want %v, got %v",
				i, tt.buf, want, got)
		}
	}
}
