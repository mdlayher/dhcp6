package dhcp6

import (
	"bytes"
	"net"
	"reflect"
	"testing"
	"time"
)

// TestIAAddrIP verifies that IAAddr.IP produces a correct net.IP value
// for an input buffer.
func TestIAAddrIP(t *testing.T) {
	var tests = []struct {
		description string
		buf         []byte
		ip          []byte
	}{
		{
			description: "nil buffer, nil IP",
		},
		{
			description: "empty buffer, nil IP",
			buf:         []byte{},
		},
		{
			description: "length 15 short buffer, nil IP",
			buf:         bytes.Repeat([]byte{1}, 15),
		},
		{
			description: "length 16 buffer, valid IP",
			buf: []byte{
				0, 0, 0, 0,
				1, 1, 1, 1,
				2, 2, 2, 2,
				3, 3, 3, 3,
			},
			ip: net.IP([]byte{
				0, 0, 0, 0,
				1, 1, 1, 1,
				2, 2, 2, 2,
				3, 3, 3, 3,
			}),
		},
		{
			description: "length 17 buffer, valid IP, ignore last byte",
			buf: []byte{
				0, 0, 0, 0,
				1, 1, 1, 1,
				2, 2, 2, 2,
				3, 3, 3, 3,
				4,
			},
			ip: net.IP([]byte{
				0, 0, 0, 0,
				1, 1, 1, 1,
				2, 2, 2, 2,
				3, 3, 3, 3,
			}),
		},
	}

	for i, tt := range tests {
		if want, got := tt.ip, IAAddr(tt.buf).IP(); !bytes.Equal(want, got) {
			t.Fatalf("[%02d] test %q, unexpected IAAddr(%v).IP():\n- want: %v\n-  got: %v",
				i, tt.description, tt.buf, want, got)
		}
	}
}

// TestIAAddrPreferredLifetime verifies that IAAddr.PreferredLifetime produces
// a correct time.Duration value for an input buffer.
func TestIAAddrPreferredLifetime(t *testing.T) {
	var tests = []struct {
		description       string
		buf               []byte
		preferredLifetime time.Duration
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
			description:       "length 4 buffer, 4m17s duration",
			buf:               []byte{0, 0, 1, 1},
			preferredLifetime: (4 * time.Minute) + 17*time.Second,
		},
		{
			description:       "length 5 buffer, 8m33s duration",
			buf:               []byte{0, 0, 2, 1, 9},
			preferredLifetime: (8 * time.Minute) + 33*time.Second,
		},
	}

	// Prepend all-zero IP value on each test
	for i, tt := range tests {
		if want, got := tt.preferredLifetime, IAAddr(append(bytes.Repeat([]byte{0}, 16), tt.buf...)).PreferredLifetime(); want != got {
			t.Fatalf("[%02d] test %q, unexpected IAAddr(%v).PreferredLifetime(): %v != %v",
				i, tt.description, tt.buf, want, got)
		}
	}
}

// TestIAAddrValidLifetime verifies that IAAddr.ValidLifetime produces a
// correct time.Duration value for an input buffer.
func TestIAAddrValidLifetime(t *testing.T) {
	var tests = []struct {
		description   string
		buf           []byte
		validLifetime time.Duration
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
			description:   "length 4 buffer, 4m17s duration",
			buf:           []byte{0, 0, 1, 1},
			validLifetime: (4 * time.Minute) + 17*time.Second,
		},
		{
			description:   "length 5 buffer, 8m33s duration",
			buf:           []byte{0, 0, 2, 1, 9},
			validLifetime: (8 * time.Minute) + 33*time.Second,
		},
	}

	// Prepend all-zero IP and PreferredLifetime value on each test
	for i, tt := range tests {
		if want, got := tt.validLifetime, IAAddr(append(bytes.Repeat([]byte{0}, 20), tt.buf...)).ValidLifetime(); want != got {
			t.Fatalf("[%02d] test %q, unexpected IAAddr(%v).ValidLifetime(): %v != %v",
				i, tt.description, tt.buf, want, got)
		}
	}
}

// TestIAAddrOptions verifies that IAAddr.Options produces a correct Options
// map for an input buffer.
func TestIAAddrOptions(t *testing.T) {
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

	// Prepend all-zero IP, preferred, and valid lifetime value on each test
	for i, tt := range tests {
		if want, got := tt.options, IAAddr(append(bytes.Repeat([]byte{0}, 24), tt.buf...)).Options(); !reflect.DeepEqual(want, got) {
			t.Fatalf("[%02d] test %q, unexpected IAAddr(%v).Options():\n- want: %v\n-  got: %v",
				i, tt.description, tt.buf, want, got)
		}
	}
}

// Test_parseIAAddr verifies that parseIAAddr produces a correct IAAddr value
// or error for an input buffer.
func Test_parseIAAddr(t *testing.T) {
	var tests = []struct {
		buf    []byte
		iaaddr IAAddr
		err    error
	}{
		{
			buf: []byte{0},
			err: errInvalidIAAddr,
		},
		{
			buf: bytes.Repeat([]byte{0}, 23),
			err: errInvalidIAAddr,
		},
		{
			buf: []byte{
				0, 0, 0, 0,
				1, 1, 1, 1,
				2, 2, 2, 2,
				3, 3, 3, 3,
				0, 0, 1, 0,
				0, 0, 2, 0,
			},
			iaaddr: IAAddr([]byte{
				0, 0, 0, 0,
				1, 1, 1, 1,
				2, 2, 2, 2,
				3, 3, 3, 3,
				0, 0, 1, 0,
				0, 0, 2, 0,
			}),
		},
	}

	for i, tt := range tests {
		iaaddr, err := parseIAAddr(tt.buf)
		if err != nil {
			if want, got := tt.err, err; want != got {
				t.Fatalf("[%02d] unexpected error for parseIAAddr(%v): %v != %v",
					i, tt.buf, want, got)
			}

			continue
		}

		if want, got := tt.iaaddr, iaaddr; !bytes.Equal(want, got) {
			t.Fatalf("[%02d] unexpected IAAddr for parseIAAddr(%v):\n- want: %v\n-  got: v",
				i, tt.buf, want, got)
		}
	}
}
