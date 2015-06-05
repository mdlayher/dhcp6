package dhcp6

import (
	"bytes"
	"net"
	"testing"
	"time"
)

// TestNewIAAddr verifies that NewIAAddr creates a proper IAAddr value or returns
// a correct error for input values.
func TestNewIAAddr(t *testing.T) {
	var tests = []struct {
		description string
		ip          net.IP
		preferred   time.Duration
		valid       time.Duration
		options     Options
		iaaddr      *IAAddr
		err         error
	}{
		{
			description: "all zero values",
			iaaddr:      &IAAddr{},
		},
		{
			description: "IPv4 address",
			ip:          net.IP([]byte{192, 168, 1, 1}),
			err:         ErrInvalidIAAddrIP,
		},
		{
			description: "preferred greater than valid lifetime",
			ip:          net.IPv6loopback,
			preferred:   2 * time.Second,
			valid:       1 * time.Second,
			err:         ErrInvalidIAAddrLifetimes,
		},
		{
			description: "IPv6 localhost, 1s preferred, 2s valid, no options",
			ip:          net.IPv6loopback,
			preferred:   1 * time.Second,
			valid:       2 * time.Second,
			iaaddr: &IAAddr{
				IP:                net.IPv6loopback,
				PreferredLifetime: 1 * time.Second,
				ValidLifetime:     2 * time.Second,
			},
		},
		{
			description: "IPv6 localhost, 1s preferred, 2s valid, option client ID [0 1]",
			ip:          net.IPv6loopback,
			preferred:   1 * time.Second,
			valid:       2 * time.Second,
			options: Options{
				OptionClientID: [][]byte{{0, 1}},
			},
			iaaddr: &IAAddr{
				IP:                net.IPv6loopback,
				PreferredLifetime: 1 * time.Second,
				ValidLifetime:     2 * time.Second,
				Options: Options{
					OptionClientID: [][]byte{{0, 1}},
				},
			},
		},
	}

	for i, tt := range tests {
		iaaddr, err := NewIAAddr(tt.ip, tt.preferred, tt.valid, tt.options)
		if err != nil {
			if want, got := tt.err, err; want != got {
				t.Fatalf("[%02d] test %q, unexpected error for NewIAAddr: %v != %v",
					i, tt.description, want, got)
			}

			continue
		}

		if want, got := tt.iaaddr.Bytes(), iaaddr.Bytes(); !bytes.Equal(want, got) {
			t.Fatalf("[%02d] test %q, unexpected IAAddr bytes:\n- want: %v\n-  got: %v",
				i, tt.description, want, got)
		}
	}
}

// TestIAAddrBytes verifies that IAAddr.Bytes allocates and returns a correct
// byte slice for a variety of input data.
func TestIAAddrBytes(t *testing.T) {
	var tests = []struct {
		description string
		iaaddr      *IAAddr
		buf         []byte
	}{
		{
			description: "empty IAAddr",
			iaaddr:      &IAAddr{},
			buf:         bytes.Repeat([]byte{0}, 24),
		},
		{
			description: "IPv6 loopback only",
			iaaddr: &IAAddr{
				IP: net.IPv6loopback,
			},
			buf: append(net.IPv6loopback, bytes.Repeat([]byte{0}, 8)...),
		},
		{
			description: "IPv6 loopback, 30s preferred, 60s valid, no options",
			iaaddr: &IAAddr{
				IP:                net.IPv6loopback,
				PreferredLifetime: 30 * time.Second,
				ValidLifetime:     60 * time.Second,
			},
			buf: append(net.IPv6loopback, []byte{
				0, 0, 0, 30,
				0, 0, 0, 60,
			}...),
		},
		{
			description: "IPv6 loopback, 30s preferred, 60s valid, option client ID [0 1]",
			iaaddr: &IAAddr{
				IP:                net.IPv6loopback,
				PreferredLifetime: 30 * time.Second,
				ValidLifetime:     60 * time.Second,
				Options: Options{
					OptionClientID: [][]byte{{0, 1}},
				},
			},
			buf: append(net.IPv6loopback, []byte{
				0, 0, 0, 30,
				0, 0, 0, 60,
				0, 1, 0, 2, 0, 1,
			}...),
		},
	}

	for i, tt := range tests {
		if want, got := tt.buf, tt.iaaddr.Bytes(); !bytes.Equal(want, got) {
			t.Fatalf("[%02d] test %q, unexpected IAAddr bytes:\n- want: %v\n-  got: %v",
				i, tt.description, want, got)
		}
	}
}

// Test_parseIAAddr verifies that parseIAAddr produces a correct IAAddr value or error
// for an input buffer.
func Test_parseIAAddr(t *testing.T) {
	var tests = []struct {
		description string
		buf         []byte
		iaaddr      *IAAddr
		err         error
	}{
		{
			description: "one byte IAAddr",
			buf:         []byte{0},
			err:         errInvalidIAAddr,
		},
		{
			description: "23 bytes IAAddr",
			buf:         bytes.Repeat([]byte{0}, 23),
			err:         errInvalidIAAddr,
		},
		{
			description: "preferred greater than valid lifetime",
			buf: append(net.IPv6zero, []byte{
				0, 0, 0, 2,
				0, 0, 0, 1,
			}...),
			err: ErrInvalidIAAddrLifetimes,
		},
		{
			description: "IPv6 loopback, 1s preferred, 2s valid, no options",
			buf: append(net.IPv6loopback, []byte{
				0, 0, 0, 1,
				0, 0, 0, 2,
			}...),
			iaaddr: &IAAddr{
				IP:                net.IPv6loopback,
				PreferredLifetime: 1 * time.Second,
				ValidLifetime:     2 * time.Second,
			},
		},
		{
			description: "IPv6 loopback, 1s preferred, 2s valid, option client ID [0 1]",
			buf: append(net.IPv6loopback, []byte{
				0, 0, 0, 1,
				0, 0, 0, 2,
				0, 1, 0, 2, 0, 1,
			}...),
			iaaddr: &IAAddr{
				IP:                net.IPv6loopback,
				PreferredLifetime: 1 * time.Second,
				ValidLifetime:     2 * time.Second,
				Options: Options{
					OptionClientID: [][]byte{{0, 1}},
				},
			},
		},
	}

	for i, tt := range tests {
		iaaddr, err := parseIAAddr(tt.buf)
		if err != nil {
			if want, got := tt.err, err; want != got {
				t.Fatalf("[%02d] test %q, unexpected error for parseIAAddr: %v != %v",
					i, tt.description, want, got)
			}

			continue
		}

		if want, got := tt.iaaddr.Bytes(), iaaddr.Bytes(); !bytes.Equal(want, got) {
			t.Fatalf("[%02d] test %q, unexpected IAAddr bytes for parseIAAddr:\n- want: %v\n-  got: %v",
				i, tt.description, want, got)
		}
	}
}
