package dhcp6

import (
	"bytes"
	"reflect"
	"testing"
	"time"
)

// TestNewIANA verifies that NewIANA creates a proper IANA value or returns
// the correct error, depending on the input values.
func TestNewIANA(t *testing.T) {
	var tests = []struct {
		description string
		iaid        []byte
		t1          time.Duration
		t2          time.Duration
		options     Options
		iana        *IANA
		err         error
	}{
		{
			description: "nil IAID, invalid IANA IAID error",
			err:         ErrInvalidIANAIAID,
		},
		{
			description: "short IAID, invalid IANA IAID error",
			iaid:        []byte{0, 1, 2},
			err:         ErrInvalidIANAIAID,
		},
		{
			description: "long IAID, invalid IANA IAID error",
			iaid:        []byte{0, 1, 2, 3, 4},
			err:         ErrInvalidIANAIAID,
		},
		{
			description: "ok IAID, 60s t1, 90s t2, nil options",
			iaid:        []byte{0, 1, 2, 3},
			t1:          60 * time.Second,
			t2:          90 * time.Second,
			iana: &IANA{
				iana: []byte{
					0, 1, 2, 3,
					0, 0, 0, 60,
					0, 0, 0, 90,
				},
			},
		},
		{
			description: "ok IAID, 3600s t1, 5400s t2, client ID [0 1] option",
			iaid:        []byte{0, 1, 2, 3},
			t1:          3600 * time.Second,
			t2:          5400 * time.Second,
			options: Options{
				OptionClientID: [][]byte{{0, 1}},
			},
			iana: &IANA{
				iana: []byte{
					0, 1, 2, 3,
					0, 0, 14, 16,
					0, 0, 21, 24,
				},
				options: Options{
					OptionClientID: [][]byte{{0, 1}},
				},
			},
		},
	}

	for i, tt := range tests {
		iana, err := NewIANA(tt.iaid, tt.t1, tt.t2, tt.options)
		if err != nil {
			if want, got := tt.err, err; want != got {
				t.Fatalf("[%02d] test %q, unexpected error for NewIANA(%v, %v, %v, %v): %v != %v",
					i, tt.description, tt.iaid, tt.t1, tt.t2, tt.options, want, got)
			}

			continue
		}

		if want, got := tt.iana.Bytes(), iana.Bytes(); !bytes.Equal(want, got) {
			t.Fatalf("[%02d] test %q, unexpected IANA bytes for NewIANA(%v, %v, %v, %v).Bytes()\n- want: %v\n-  got: %v",
				i, tt.description, tt.iaid, tt.t1, tt.t2, tt.options, want, got)
		}
	}
}

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
		if want, got := tt.iaid, (&IANA{iana: tt.buf}).IAID(); !bytes.Equal(want, got) {
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
		if want, got := tt.t1, (&IANA{
			iana: append([]byte{0, 0, 0, 0}, tt.buf...),
		}).T1(); want != got {
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

	// Prepend all-zero IAID and T1 values on each test
	for i, tt := range tests {
		if want, got := tt.t2, (&IANA{
			iana: append(bytes.Repeat([]byte{0}, 8), tt.buf...),
		}).T2(); want != got {
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
				OptionClientID: [][]byte{{0, 1}},
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
					{0, 1},
					{0, 2},
				},
			},
		},
	}

	// Prepend all-zero IAID, T1, and T2 values on each test
	for i, tt := range tests {
		iana, err := parseIANA(append(bytes.Repeat([]byte{0}, 12), tt.buf...))
		if err != nil {
			t.Fatal(err)
		}

		if want, got := tt.options, iana.Options(); !reflect.DeepEqual(want, got) {
			t.Fatalf("[%02d] test %q, unexpected IANA(%v).Options():\n- want: %v\n-  got: %v",
				i, tt.description, tt.buf, want, got)
		}
	}
}

// Test_parseIANA verifies that parseIANA produces a correct IANA value or error
// for an input buffer.
func Test_parseIANA(t *testing.T) {
	var tests = []struct {
		buf     []byte
		iana    *IANA
		options Options
		err     error
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
				0, 1, 0, 2, 0, 1,
			},
			iana: &IANA{
				iana: []byte{
					1, 2, 3, 4,
					0, 0, 1, 0,
					0, 0, 2, 0,
				},
				options: Options{
					OptionClientID: [][]byte{{0, 1}},
				},
			},
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

		if want, got := tt.iana, iana; !reflect.DeepEqual(want, got) {
			t.Fatalf("[%02d] unexpected IANA for parseIANA(%v):\n- want: %v\n-  got: %v",
				i, tt.buf, want, got)
		}
	}
}
