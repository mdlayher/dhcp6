package dhcp6

import (
	"bytes"
	"reflect"
	"testing"
)

// TestNewIATA verifies that NewIATA creates a proper IATA value for
// input values.
func TestNewIATA(t *testing.T) {
	var tests = []struct {
		description string
		iaid        [4]byte
		options     Options
		iata        *IATA
	}{
		{
			description: "all zero values",
			iata:        &IATA{},
		},
		{
			description: "[0 1 2 3] IAID, option client ID [0 1]",
			iaid:        [4]byte{0, 1, 2, 3},
			options: Options{
				OptionClientID: [][]byte{[]byte{0, 1}},
			},
			iata: &IATA{
				IAID: [4]byte{0, 1, 2, 3},
				Options: Options{
					OptionClientID: [][]byte{[]byte{0, 1}},
				},
			},
		},
	}

	for i, tt := range tests {
		iata := NewIATA(tt.iaid, tt.options)

		if want, got := tt.iata.Bytes(), iata.Bytes(); !reflect.DeepEqual(want, got) {
			t.Fatalf("[%02d] test %q, unexpected IATA bytes for NewIATA(%v, %v)\n- want: %v\n-  got: %v",
				i, tt.description, tt.iaid, tt.options, want, got)
		}
	}
}

// Test_parseIATA verifies that parseIATA produces a correct IATA value or error
// for an input buffer.
func Test_parseIATA(t *testing.T) {
	var tests = []struct {
		buf     []byte
		iata    *IATA
		options Options
		err     error
	}{
		{
			buf: []byte{0},
			err: errInvalidIATA,
		},
		{
			buf: bytes.Repeat([]byte{0}, 3),
			err: errInvalidIATA,
		},
		{
			buf: []byte{
				1, 2, 3, 4,
				0, 1, 0, 2, 0, 1,
			},
			iata: &IATA{
				IAID: [4]byte{1, 2, 3, 4},
				Options: Options{
					OptionClientID: [][]byte{{0, 1}},
				},
			},
		},
	}

	for i, tt := range tests {
		iata, err := parseIATA(tt.buf)
		if err != nil {
			if want, got := tt.err, err; want != got {
				t.Fatalf("[%02d] unexpected error for parseIATA(%v): %v != %v",
					i, tt.buf, want, got)
			}

			continue
		}

		if want, got := tt.iata, iata; !reflect.DeepEqual(want, got) {
			t.Fatalf("[%02d] unexpected IATA for parseIATA(%v):\n- want: %v\n-  got: %v",
				i, tt.buf, want, got)
		}
	}
}
