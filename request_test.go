package dhcp6

import (
	"net"
	"reflect"
	"testing"
)

// Test_newServerRequest verifies that newServerRequest returns a consistent
// Request struct for use in Handler types.
func Test_newServerRequest(t *testing.T) {
	opt := option{
		Code: OptionClientID,
		Data: []byte{0, 1},
	}
	p, err := newPacket(MessageTypeSolicit, []byte{1, 2, 3}, Options{
		opt.Code: [][]byte{opt.Data},
	})
	if err != nil {
		t.Fatal(err)
	}

	addr := &net.UDPAddr{
		IP:   net.ParseIP("::1"),
		Port: 546,
	}

	r := &Request{
		MessageType:   p.MessageType(),
		TransactionID: p.TransactionID(),
		Options:       make(Options),
		Length:        int64(len(p)),
		RemoteAddr:    "[::1]:546",

		packet: p,
	}
	r.Options.AddRaw(opt.Code, opt.Data)

	if want, got := r, newServerRequest(p, addr); !reflect.DeepEqual(want, got) {
		t.Fatalf("unexpected Request for newServerRequest(%v, %v)\n- want: %v\n-  got: %v",
			p, addr, want, got)
	}
}
