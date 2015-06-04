package dhcp6

import (
	"bytes"
	"reflect"
	"testing"
)

// TestPacketMessageType verifies that Packet.MessageType returns a correct
// message type value from a byte, and that it returns an error if the byte
// is empty.
func TestPacketMessageType(t *testing.T) {
	var tests = []struct {
		description string
		buf         []byte
		mt          MessageType
		err         error
	}{
		{
			description: "nil buffer, malformed packet",
			err:         ErrMalformedPacket,
		},
		{
			description: "empty buffer, malformed packet",
			buf:         []byte{},
			err:         ErrMalformedPacket,
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
		mt, err := Packet(tt.buf).MessageType()
		if err != nil {
			if want, got := tt.err, err; want != got {
				t.Fatalf("[%02d] test %q, unexpected error: %v != %v",
					i, tt.description, want, got)
			}

			continue
		}

		if want, got := tt.mt, mt; want != got {
			t.Fatalf("[%02d] test %q, unexpected Packet(%v).MessageType(): %v != %v",
				i, tt.description, tt.buf, want, got)
		}
	}
}

// TestPacketTransactionID verifies that Packet.TransactionID returns a correct
// transaction ID value from a slice of bytes, and that it returns an error if
// the byte slice is too short to contain a transaction ID.
func TestPacketTransactionID(t *testing.T) {
	var tests = []struct {
		description string
		buf         []byte
		txID        []byte
		err         error
	}{
		{
			description: "nil buffer, malformed packet",
			err:         ErrMalformedPacket,
		},
		{
			description: "empty buffer, malformed packet",
			buf:         []byte{},
			err:         ErrMalformedPacket,
		},
		{
			description: "too short buffer (1 byte), malformed packet",
			buf:         []byte{0},
			err:         ErrMalformedPacket,
		},
		{
			description: "too short buffer (2 bytes), malformed packet",
			buf:         []byte{0, 0},
			err:         ErrMalformedPacket,
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
		txID, err := Packet(append([]byte{0}, tt.buf...)).TransactionID()
		if err != nil {
			if want, got := tt.err, err; want != got {
				t.Fatalf("[%02d] test %q, unexpected error: %v != %v",
					i, tt.description, want, got)
			}

			continue
		}

		if want, got := tt.txID, txID; !bytes.Equal(want, got) {
			t.Fatalf("[%02d] test %q, unexpected Packet(%v).TransactionID(): %v != %v",
				i, tt.description, tt.buf, want, got)
		}
	}
}

// TestPacketOptions verifies that Packet.Options returns a correct
// Options map from a slice of bytes, and that it returns an error if
// the byte slice is too short to contain an Options map.
func TestPacketOptions(t *testing.T) {
	var tests = []struct {
		description string
		buf         []byte
		options     Options
		err         error
	}{
		{
			description: "nil buffer, malformed packet",
			err:         ErrMalformedPacket,
		},
		{
			description: "empty buffer, malformed packet",
			buf:         []byte{},
			err:         ErrMalformedPacket,
		},
		{
			description: "too short buffer (1 byte), malformed packet",
			buf:         []byte{0},
			err:         ErrMalformedPacket,
		},
		{
			description: "too short buffer (3 bytes), malformed packet",
			buf:         []byte{0, 0, 0},
			err:         ErrMalformedPacket,
		},
		{
			description: "ok buffer, no options",
			buf:         []byte{0, 0, 0, 0},
			options:     Options{},
		},
		{
			description: "ok buffer, client ID option",
			buf:         []byte{0, 0, 0, 0, 0, 1, 0, 2, 0, 1},
			options: Options{
				OptionClientID: [][]byte{[]byte{0, 1}},
			},
		},
	}

	for i, tt := range tests {
		options, err := Packet(tt.buf).Options()
		if err != nil {
			if want, got := tt.err, err; want != got {
				t.Fatalf("[%02d] test %q, unexpected error: %v != %v",
					i, tt.description, want, got)
			}

			continue
		}

		if want, got := tt.options, options; !reflect.DeepEqual(want, got) {
			t.Fatalf("[%02d] test %q, unexpected Packet(%v).Options(): %v != %v",
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

		mt, err := p.MessageType()
		if err != nil {
			t.Fatal(err)
		}

		if want, got := tt.mt, mt; want != got {
			t.Fatalf("[%02d] test %q, unexpected Packet message type: %v != %v",
				i, tt.description, want, got)
		}

		txID, err := p.TransactionID()
		if err != nil {
			t.Fatal(err)
		}

		if want, got := tt.txID, txID; !bytes.Equal(want, got) {
			t.Fatalf("[%02d] test %q, unexpected Packet transaction ID:\n- want: %v\n-  got: %v",
				i, tt.description, want, got)
		}

		options, err := p.Options()
		if err != nil {
			t.Fatal(err)
		}

		if want, got := tt.options, options; !reflect.DeepEqual(want, got) {
			t.Fatalf("[%02d] test %q, unexpected options slice:\n- want: %v\n-  got: %v",
				i, tt.description, want, got)
		}
	}
}

// TestParsePacket verifies that ParsePacket returns appropriate errors for
// various input byte slices.
func TestParsePacket(t *testing.T) {
	var tests = []struct {
		description string
		buf         []byte
		err         error
	}{
		{
			description: "nil buffer, malformed packet",
			err:         ErrMalformedPacket,
		},
		{
			description: "empty buffer, malformed packet",
			buf:         []byte{},
			err:         ErrMalformedPacket,
		},
		{
			description: "length 1 buffer, malformed packet",
			buf:         []byte{0},
			err:         ErrMalformedPacket,
		},
		{
			description: "length 3 buffer, malformed packet",
			buf:         []byte{0, 0, 0},
			err:         ErrMalformedPacket,
		},
		{
			description: "length 4 buffer, OK",
			buf:         []byte{0, 0, 0, 0},
		},
		{
			description: "length 5 buffer, OK",
			buf:         []byte{0, 0, 0, 0, 0},
		},
	}

	for i, tt := range tests {
		_, err := ParsePacket(tt.buf)
		if want, got := tt.err, err; want != got {
			t.Fatalf("[%02d] test %q, unexpected error: %v != %v",
				i, tt.description, want, got)
		}
	}
}
