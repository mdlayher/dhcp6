package dhcp6

import (
	"bytes"
	"reflect"
	"testing"
)

// TestPacketBytes verifies that Packet.Bytes allocates and returns a correct
// byte slice for a variety of input data.
func TestPacketBytes(t *testing.T) {
	var tests = []struct {
		description string
		packet      *Packet
		buf         []byte
	}{
		{
			description: "empty packet",
			packet:      &Packet{},
			buf:         []byte{0, 0, 0, 0},
		},
		{
			description: "Solicit only",
			packet: &Packet{
				MessageType: MessageTypeSolicit,
			},
			buf: []byte{1, 0, 0, 0},
		},
		{
			description: "Solicit, [1 2 3] transaction ID",
			packet: &Packet{
				MessageType:   MessageTypeSolicit,
				TransactionID: [3]byte{1, 2, 3},
			},
			buf: []byte{1, 1, 2, 3},
		},
		{
			description: "Solicit, [2, 3, 4] transaction ID, option client ID [0 1]",
			packet: &Packet{
				MessageType:   MessageTypeSolicit,
				TransactionID: [3]byte{1, 2, 3},
				Options: Options{
					OptionClientID: [][]byte{[]byte{0, 1}},
				},
			},
			buf: []byte{1, 1, 2, 3, 0, 1, 0, 2, 0, 1},
		},
	}

	for i, tt := range tests {
		if want, got := tt.buf, tt.packet.Bytes(); !bytes.Equal(want, got) {
			t.Fatalf("[%02d] test %q, unexpected packet bytes:\n- want: %v\n-  got: %v",
				i, tt.description, want, got)
		}
	}
}

// Test_parsePacket verifies that parsePacket returns appropriate Packets and
// errors for various input byte slices.
func Test_parsePacket(t *testing.T) {
	var tests = []struct {
		description string
		buf         []byte
		packet      *Packet
		err         error
	}{
		{
			description: "nil buffer, malformed packet",
			err:         errInvalidPacket,
		},
		{
			description: "empty buffer, malformed packet",
			buf:         []byte{},
			err:         errInvalidPacket,
		},
		{
			description: "length 1 buffer, malformed packet",
			buf:         []byte{0},
			err:         errInvalidPacket,
		},
		{
			description: "length 3 buffer, malformed packet",
			buf:         []byte{0, 0, 0},
			err:         errInvalidPacket,
		},
		{
			description: "length 4 buffer, OK",
			buf:         []byte{0, 0, 0, 0},
			packet: &Packet{
				MessageType:   0,
				TransactionID: [3]byte{0, 0, 0},
				Options:       make(Options),
			},
		},
		{
			description: "Solicit, [1 2 3] transaction ID, OK",
			buf:         []byte{1, 1, 2, 3},
			packet: &Packet{
				MessageType:   MessageTypeSolicit,
				TransactionID: [3]byte{1, 2, 3},
				Options:       make(Options),
			},
		},
		{
			description: "Solicit, [2 3 4] transaction ID, option client ID [0 1], OK",
			buf:         []byte{1, 2, 3, 4, 0, 1, 0, 2, 0, 1},
			packet: &Packet{
				MessageType:   MessageTypeSolicit,
				TransactionID: [3]byte{2, 3, 4},
				Options: Options{
					OptionClientID: [][]byte{[]byte{0, 1}},
				},
			},
		},
	}

	for i, tt := range tests {
		p, err := parsePacket(tt.buf)
		if err != nil {
			if want, got := tt.err, err; want != got {
				t.Fatalf("[%02d] test %q, unexpected error: %v != %v",
					i, tt.description, want, got)
			}

			continue
		}

		if want, got := tt.packet, p; !reflect.DeepEqual(want, got) {
			t.Fatalf("[%02d] test %q, unexpected packet:\n- want: %v\n-  got: %v",
				i, tt.description, want, got)
		}
	}
}
