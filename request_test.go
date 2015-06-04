package dhcp6

import (
	"net"
	"reflect"
	"testing"
)

// TestParseRequest verifies that newServerRequest returns a consistent
// Request struct for use in Handler types.
func TestParseRequest(t *testing.T) {
	opt := option{
		Code: OptionClientID,
		Data: []byte{0, 1},
	}
	p, err := NewPacket(MessageTypeSolicit, []byte{1, 2, 3}, Options{
		opt.Code: [][]byte{opt.Data},
	})
	if err != nil {
		t.Fatal(err)
	}

	addr := &net.UDPAddr{
		IP:   net.ParseIP("::1"),
		Port: 546,
	}

	mt, err := p.MessageType()
	if err != nil {
		t.Fatal(err)
	}

	txID, err := p.TransactionID()
	if err != nil {
		t.Fatal(err)
	}

	r := &Request{
		MessageType:   mt,
		TransactionID: txID,
		Options:       make(Options),
		Length:        int64(len(p)),
		RemoteAddr:    "[::1]:546",

		packet: p,
	}
	r.Options.AddRaw(opt.Code, opt.Data)

	gotR, err := ParseRequest(p, addr)
	if err != nil {
		t.Fatal(err)
	}

	if want, got := r, gotR; !reflect.DeepEqual(want, got) {
		t.Fatalf("unexpected Request for ParseRequest(%v, %v)\n- want: %v\n-  got: %v",
			p, addr, want, got)
	}
}
