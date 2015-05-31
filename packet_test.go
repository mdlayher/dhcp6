package dhcp6

import (
	"bytes"
	"reflect"
	"testing"
)

// TestPacketMessageType verifies that Packet.MessageType returns a correct
// message type value from a byte, and that it returns a zero value if the
// message type byte is empty.
func TestPacketMessageType(t *testing.T) {
	var tests = []struct {
		description string
		buf         []byte
		mt          MessageType
	}{
		{
			description: "nil buffer, zero message type",
			buf:         nil,
			mt:          MessageType(0),
		},
		{
			description: "empty buffer, zero message type",
			buf:         []byte{},
			mt:          MessageType(0),
		},
		{
			description: "buffer with one zero, message type 0",
			buf:         []byte{0},
			mt:          MessageType(0),
		},
		{
			description: "buffer with one 1, Solicit message type",
			buf:         []byte{1},
			mt:          MessageTypeSolicit,
		},
		{
			description: "buffer with one 3, Request message type",
			buf:         []byte{3},
			mt:          MessageTypeRequest,
		},
		{
			description: "buffer with one 5, Renew message type",
			buf:         []byte{5},
			mt:          MessageTypeRenew,
		},
		{
			description: "buffer with one 99, message type 99",
			buf:         []byte{99},
			mt:          MessageType(99),
		},
	}

	for i, tt := range tests {
		if want, got := tt.mt, Packet(tt.buf).MessageType(); want != got {
			t.Fatalf("[%02d] test %q, unexpected Packet(%v).MessageType(): %v != %v",
				i, tt.description, tt.buf, want, got)
		}
	}
}

// TestPacketTransactionID verifies that Packet.TransactionID returns a correct
// transaction ID value from a slice of bytes, and that it returns nil if the
// byte slice is too short to contain a transaction ID.
func TestPacketTransactionID(t *testing.T) {
	var tests = []struct {
		description string
		buf         []byte
		txID        []byte
	}{
		{
			description: "nil buffer, nil transaction ID",
			buf:         nil,
			txID:        nil,
		},
		{
			description: "empty buffer, nil transaction ID",
			buf:         []byte{},
			txID:        nil,
		},
		{
			description: "too short buffer (1 byte), nil transaction ID",
			buf:         []byte{0},
			txID:        nil,
		},
		{
			description: "too short buffer (2 bytes), nil transaction ID",
			buf:         []byte{0, 0},
			txID:        nil,
		},
		{
			description: "[0 0 0] buffer, [0 0 0] transaction ID",
			buf:         []byte{0, 0, 0},
			txID:        []byte{0, 0, 0},
		},
		{
			description: "[1 2 3] buffer, [1 2 3] transaction ID",
			buf:         []byte{1, 2, 3},
			txID:        []byte{1, 2, 3},
		},
		{
			description: "[1 2 3 4] buffer, [1 2 3] transaction ID (ignore extra byte)",
			buf:         []byte{1, 2, 3, 4},
			txID:        []byte{1, 2, 3},
		},
	}

	// Message type is not relevant in this test, so we automatically
	// prepend an empty message type
	for i, tt := range tests {
		if want, got := tt.txID, Packet(append([]byte{0}, tt.buf...)).TransactionID(); !bytes.Equal(want, got) {
			t.Fatalf("[%02d] test %q, unexpected Packet(%v).TransactionID(): %v != %v",
				i, tt.description, tt.buf, want, got)
		}
	}
}

// TestNewPacket verifies that NewPacket generates an appropriate output Packet,
// when provided with a variety of message types, (possibly erroneous)
// transaction IDs, and options.
func TestNewPacket(t *testing.T) {
	var tests = []struct {
		description string
		mt          MessageType
		txID        []byte
		options     Options
		err         error
	}{
		{
			description: "solicit, tx 11, no options, invalid transaction ID",
			mt:          MessageTypeSolicit,
			txID:        []byte{1, 1},
			options:     Options{},
			err:         ErrInvalidTransactionID,
		},
		{
			description: "solicit, tx 111, no options",
			mt:          MessageTypeSolicit,
			txID:        []byte{1, 1, 1},
			options:     Options{},
		},
		{
			description: "renew, tx 012, option client ID foo",
			mt:          MessageTypeRenew,
			txID:        []byte{0, 1, 2},
			options: Options{
				OptionClientID: [][]byte{[]byte("foo")},
			},
		},
		{
			description: "release, tx 345, multiple options",
			mt:          MessageTypeRenew,
			txID:        []byte{0, 1, 2},
			options: Options{
				OptionClientID:    [][]byte{[]byte("foo")},
				OptionElapsedTime: [][]byte{[]byte("0123")},
			},
		},
	}

	for i, tt := range tests {
		p, err := NewPacket(tt.mt, tt.txID, tt.options)
		if err != nil && tt.err == nil {
			t.Fatal(err)
		}
		if want, got := tt.err, err; want != got {
			t.Fatalf("[%02d] test %q, unexpected error: %v != %v",
				i, tt.description, want, got)
		}
		if err != nil {
			continue
		}

		if want, got := tt.mt, p.MessageType(); want != got {
			t.Fatalf("[%02d] test %q, unexpected Packet message type: %v != %v",
				i, tt.description, want, got)
		}

		if want, got := tt.txID, p.TransactionID(); !bytes.Equal(want, got) {
			t.Fatalf("[%02d] test %q, unexpected Packet transaction ID:\n- want: %v\n-  got: %v",
				i, tt.description, want, got)
		}

		if want, got := tt.options, p.Options(); !reflect.DeepEqual(want, got) {
			t.Fatalf("[%02d] test %q, unexpected options slice:\n- want: %v\n-  got: %v",
				i, tt.description, want, got)
		}
	}
}
