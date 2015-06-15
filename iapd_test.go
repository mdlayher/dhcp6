package dhcp6

import (
	"bytes"
	"reflect"
	"testing"
	"time"
)

// TestNewIAPD verifies that NewIAPD creates a proper IAPD value for
// input values.
func TestNewIAPD(t *testing.T) {
	var tests = []struct {
		description string
		iaid        [4]byte
		t1          time.Duration
		t2          time.Duration
		options     Options
		iapd        *IAPD
	}{
		{
			description: "all zero values",
			iapd:        &IAPD{},
		},
		{
			description: "[0 1 2 3] IAID, 30s T1, 60s T2, option client ID [0 1]",
			iaid:        [4]byte{0, 1, 2, 3},
			t1:          30 * time.Second,
			t2:          60 * time.Second,
			options: Options{
				OptionClientID: [][]byte{[]byte{0, 1}},
			},
			iapd: &IAPD{
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
		iapd := NewIAPD(tt.iaid, tt.t1, tt.t2, tt.options)

		if want, got := tt.iapd.Bytes(), iapd.Bytes(); !reflect.DeepEqual(want, got) {
			t.Fatalf("[%02d] test %q, unexpected IAPD bytes for NewIAPD(%v, %v, %v, %v)\n- want: %v\n-  got: %v",
				i, tt.description, tt.iaid, tt.t1, tt.t2, tt.options, want, got)
		}
	}
}

// Test_parseIAPD verifies that parseIAPD produces a correct IAPD value or error
// for an input buffer.
func Test_parseIAPD(t *testing.T) {
	var tests = []struct {
		buf     []byte
		iapd    *IAPD
		options Options
		err     error
	}{
		{
			buf: []byte{0},
			err: errInvalidIAPD,
		},
		{
			buf: bytes.Repeat([]byte{0}, 11),
			err: errInvalidIAPD,
		},
		{
			buf: []byte{
				1, 2, 3, 4,
				0, 0, 1, 0,
				0, 0, 2, 0,
				0, 1, 0, 1,
			},
			err: errInvalidOptions,
		},
		{
			buf: []byte{
				1, 2, 3, 4,
				0, 0, 1, 0,
				0, 0, 2, 0,
				0, 1, 0, 2, 0, 1,
			},
			iapd: &IAPD{
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
		iapd, err := parseIAPD(tt.buf)
		if err != nil {
			if want, got := tt.err, err; want != got {
				t.Fatalf("[%02d] unexpected error for parseIAPD(%v): %v != %v",
					i, tt.buf, want, got)
			}

			continue
		}

		if want, got := tt.iapd, iapd; !reflect.DeepEqual(want, got) {
			t.Fatalf("[%02d] unexpected IAPD for parseIAPD(%v):\n- want: %v\n-  got: %v",
				i, tt.buf, want, got)
		}
	}
}
