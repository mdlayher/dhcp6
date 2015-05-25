package dhcp6

import (
	"bytes"
	"reflect"
	"testing"
	"time"
)

// TestIANAIAID verifies that IANA.IAID produces a correct IAID byte slice
// for an input buffer.
func TestIANAIAID(t *testing.T) {
	var tests = []struct {
		description string
		buf         []byte
		iaid        []byte
	}{
		{
			description: "nil buffer, nil IAID",
		},
		{
			description: "empty buffer, nil IAID",
			buf:         []byte{},
		},
		{
			description: "length 3 short buffer, nil IAID",
			buf:         []byte{1, 2, 3},
		},
		{
			description: "length 4 buffer, [1 2 3 4] IAID",
			buf:         []byte{1, 2, 3, 4},
			iaid:        []byte{1, 2, 3, 4},
		},
		{
			description: "length 5 buffer, [2 3 4 5] IAID",
			buf:         []byte{2, 3, 4, 5, 6},
			iaid:        []byte{2, 3, 4, 5},
		},
	}

	for i, tt := range tests {
		if want, got := tt.iaid, IANA(tt.buf).IAID(); !bytes.Equal(want, got) {
			t.Fatalf("[%02d] test %q, unexpected IANA(%v).IAID():\n- want: %v\n-  got: %v",
				i, tt.description, tt.buf, want, got)
		}
	}
}

// TestIANAT1 verifies that IANA.T1 produces a correct T1 time.Duration for
// an input buffer.
func TestIANAT1(t *testing.T) {
	var tests = []struct {
		description string
		buf         []byte
		t1          time.Duration
	}{
		{
			description: "nil buffer, zero duration",
		},
		{
			description: "empty buffer, zero duration",
			buf:         []byte{},
		},
		{
			description: "length 3 short buffer, zero duration",
			buf:         []byte{1, 2, 3},
		},
		{
			description: "length 4 buffer, 4m17s duration",
			buf:         []byte{0, 0, 1, 1},
			t1:          (4 * time.Minute) + 17*time.Second,
		},
		{
			description: "length 5 buffer, 8m33s duration",
			buf:         []byte{0, 0, 2, 1, 9},
			t1:          (8 * time.Minute) + 33*time.Second,
		},
	}

	// Prepend all-zero IAID value on each test
	for i, tt := range tests {
		if want, got := tt.t1, IANA(append([]byte{0, 0, 0, 0}, tt.buf...)).T1(); want != got {
			t.Fatalf("[%02d] test %q, unexpected IANA(%v).T1(): %v != %v",
				i, tt.description, tt.buf, want, got)
		}
	}
}

// TestIANAT2 verifies that IANA.T2 produces a correct T2 time.Duration for
// an input buffer.
func TestIANAT2(t *testing.T) {
	var tests = []struct {
		description string
		buf         []byte
		t2          time.Duration
	}{
		{
			description: "nil buffer, zero duration",
		},
		{
			description: "empty buffer, zero duration",
			buf:         []byte{},
		},
		{
			description: "length 3 short buffer, zero duration",
			buf:         []byte{1, 2, 3},
		},
		{
			description: "length 4 buffer, 4m17s duration",
			buf:         []byte{0, 0, 1, 1},
			t2:          (4 * time.Minute) + 17*time.Second,
		},
		{
			description: "length 5 buffer, 8m33s duration",
			buf:         []byte{0, 0, 2, 1, 9},
			t2:          (8 * time.Minute) + 33*time.Second,
		},
	}

	// Prepend all-zero T1 value on each test
	for i, tt := range tests {
		if want, got := tt.t2, IANA(append(bytes.Repeat([]byte{0}, 8), tt.buf...)).T2(); want != got {
			t.Fatalf("[%02d] test %q, unexpected IANA(%v).T2(): %v != %v",
				i, tt.description, tt.buf, want, got)
		}
	}
}

// TestIANAOptions verifies that IANA.Options produces a correct Options time.Duration for
// an input buffer.
func TestIANAOptions(t *testing.T) {
	var tests = []struct {
		description string
		buf         []byte
		options     Options
	}{
		{
			description: "nil buffer, empty options",
			options:     Options{},
		},
		{
			description: "empty buffer, empty options",
			buf:         []byte{},
			options:     Options{},
		},
		{
			description: "short buffer, empty options",
			buf:         []byte{0, 0, 0},
			options:     Options{},
		},
		{
			description: "ok buffer, one OptionClientID option",
			buf:         []byte{0, 1, 0, 2, 0, 1},
			options: Options{
				OptionClientID: [][]byte{[]byte{0, 1}},
			},
		},
		{
			description: "ok buffer, two OptionClientID options",
			buf: []byte{
				0, 1, 0, 2, 0, 1,
				0, 1, 0, 2, 0, 2,
			},
			options: Options{
				OptionClientID: [][]byte{
					[]byte{0, 1},
					[]byte{0, 2},
				},
			},
		},
	}

	// Prepend all-zero IAID value on each test
	for i, tt := range tests {
		if want, got := tt.options, IANA(append(bytes.Repeat([]byte{0}, 12), tt.buf...)).Options(); !reflect.DeepEqual(want, got) {
			t.Fatalf("[%02d] test %q, unexpected IANA(%v).Options():\n- want: %v\n-  got: %v",
				i, tt.description, tt.buf, want, got)
		}
	}
}

// Test_parseIANA verifies that parseIANA produces a correct IANA value or error
// for an input buffer.
func Test_parseIANA(t *testing.T) {
	var tests = []struct {
		buf  []byte
		iana IANA
		err  error
	}{
		{
			buf: []byte{0},
			err: errInvalidIANA,
		},
		{
			buf: bytes.Repeat([]byte{0}, 11),
			err: errInvalidIANA,
		},
		{
			buf: []byte{
				1, 2, 3, 4,
				0, 0, 1, 0,
				0, 0, 2, 0,
			},
			iana: IANA([]byte{
				1, 2, 3, 4,
				0, 0, 1, 0,
				0, 0, 2, 0,
			}),
		},
	}

	for i, tt := range tests {
		iana, err := parseIANA(tt.buf)
		if err != nil {
			if want, got := tt.err, err; want != got {
				t.Fatalf("[%02d] unexpected error for parseIANA(%v): %v != %v",
					i, tt.buf, want, got)
			}

			continue
		}

		if want, got := tt.iana, iana; !bytes.Equal(want, got) {
			t.Fatalf("[%02d] unexpected IANA for parseIANA(%v):\n- want: %v\n-  got: v",
				i, tt.buf, want, got)
		}
	}
}
