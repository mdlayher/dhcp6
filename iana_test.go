package dhcp6

import (
	"bytes"
	"reflect"
	"testing"
	"time"
)

// TestNewIANA verifies that NewIANA creates a proper IANA value for
// input values.
func TestNewIANA(t *testing.T) {
	var tests = []struct {
		description string
		iaid        [4]byte
		t1          time.Duration
		t2          time.Duration
		options     Options
		iana        *IANA
	}{
		{
			description: "all zero values",
			iana:        &IANA{},
		},
		{
			description: "[0 1 2 3] IAID, 30s T1, 60s T2, option client ID [0 1]",
			iaid:        [4]byte{0, 1, 2, 3},
			t1:          30 * time.Second,
			t2:          60 * time.Second,
			options: Options{
				OptionClientID: [][]byte{[]byte{0, 1}},
			},
			iana: &IANA{
				IAID: [4]byte{0, 1, 2, 3},
				T1:   30 * time.Second,
				T2:   60 * time.Second,
				Options: Options{
					OptionClientID: [][]byte{[]byte{0, 1}},
				},
			},
		},
	}

	for i, tt := range tests {
		iana := NewIANA(tt.iaid, tt.t1, tt.t2, tt.options)

		if want, got := tt.iana.Bytes(), iana.Bytes(); !reflect.DeepEqual(want, got) {
			t.Fatalf("[%02d] test %q, unexpected IANA bytes for NewIANA(%v, %v, %v, %v)\n- want: %v\n-  got: %v",
				i, tt.description, tt.iaid, tt.t1, tt.t2, tt.options, want, got)
		}
	}
}

// TestIANABytes verifies that IANA.Bytes allocates and returns a correct
// byte slice for a variety of input data.
func TestIANABytes(t *testing.T) {
	var tests = []struct {
		description string
		iana        *IANA
		buf         []byte
	}{
		{
			description: "empty IANA",
			iana:        &IANA{},
			buf: []byte{
				0, 0, 0, 0,
				0, 0, 0, 0,
				0, 0, 0, 0,
			},
		},
		{
			description: "[1 2 3 4] IAID only",
			iana: &IANA{
				IAID: [4]byte{1, 2, 3, 4},
			},
			buf: []byte{
				1, 2, 3, 4,
				0, 0, 0, 0,
				0, 0, 0, 0,
			},
		},
		{
			description: "[1 2 3 4] IAID, 30s T1, 60s T2",
			iana: &IANA{
				IAID: [4]byte{1, 2, 3, 4},
				T1:   30 * time.Second,
				T2:   60 * time.Second,
			},
			buf: []byte{
				1, 2, 3, 4,
				0, 0, 0, 30,
				0, 0, 0, 60,
			},
		},
		{
			description: "[1 2 3 4] IAID, 30s T1, 60s T2, option client ID [0 1]",
			iana: &IANA{
				IAID: [4]byte{1, 2, 3, 4},
				T1:   30 * time.Second,
				T2:   60 * time.Second,
				Options: Options{
					OptionClientID: [][]byte{[]byte{0, 1}},
				},
			},
			buf: []byte{
				1, 2, 3, 4,
				0, 0, 0, 30,
				0, 0, 0, 60,
				0, 1, 0, 2, 0, 1,
			},
		},
	}

	for i, tt := range tests {
		if want, got := tt.buf, tt.iana.Bytes(); !bytes.Equal(want, got) {
			t.Fatalf("[%02d] test %q, unexpected IANA bytes:\n- want: %v\n-  got: %v",
				i, tt.description, want, got)
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
				IAID: [4]byte{1, 2, 3, 4},
				T1:   (4 * time.Minute) + 16*time.Second,
				T2:   (8 * time.Minute) + 32*time.Second,
				Options: Options{
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
