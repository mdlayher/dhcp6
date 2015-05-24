package dhcp6

import (
	"bytes"
	"net"
	"testing"

	"golang.org/x/net/ipv6"
)

// TestServer_newConn verifies that Server.newConn creates a consistent conn
// struct from input values.
func TestServer_newConn(t *testing.T) {
	addr := &net.UDPAddr{
		IP:   net.ParseIP("::1"),
		Port: 546,
	}
	n := 3
	buf := []byte{0, 1, 2, 3}

	c, err := (&Server{}).newConn(nil, addr, n, buf)
	if err != nil {
		t.Fatal(err)
	}

	if want, got := addr, c.remoteAddr; want != got {
		t.Fatalf("unexpected addr: %v != %v", want, got)
	}
	if want, got := n, len(c.buf); want != got {
		t.Fatalf("unexpected len(buf): %v != %v", want, got)
	}
	if want, got := n, cap(c.buf); want != got {
		t.Fatalf("unexpected cap(buf): %v != %v", want, got)
	}
	if want, got := buf[:n], c.buf; !bytes.Equal(want, got) {
		t.Fatalf("unexpected cap(buf):\n- want: %v\n  -got: %v", want, got)
	}
}

// Test_conn_serve verifies that conn.serve invokes a Handler with correct
// Request and Responser values.
func Test_conn_serve(t *testing.T) {
	option := Option{
		Code: OptionClientID,
		Data: []byte{0, 1},
	}
	options := []Option{option}

	p, err := newPacket(MessageTypeSolicit, []byte{0, 1, 2}, options)
	if err != nil {
		t.Fatal(err)
	}

	// Though this data is not actually representative of a DHCP response,
	// it will confirm that conn.serve acts as intended
	var response = []byte("helloworld")

	addr := &net.UDPAddr{
		IP:   net.IP("::1"),
		Port: 546,
	}

	// Create a DHCP handler and verify every possible field for correctness
	tc := testConnServe(t, p, addr, func(w Responser, r *Request) {
		if want, got := p.MessageType(), r.MessageType; want != got {
			t.Fatalf("unexpected message type: %v != %v", want, got)
		}

		if want, got := p.TransactionID(), r.TransactionID; !bytes.Equal(want, got) {
			t.Fatalf("unexpected transaction ID:\n- want: %v\n-  got: %v", want, got)
		}

		if want, got := len(options), len(r.Options); want != got {
			t.Fatalf("unexpected options length: %v != %v", want, got)
		}

		duid, ok, err := r.Options.ClientID()
		if err != nil {
			t.Fatal(err)
		}
		if !ok {
			t.Fatal("no client ID found in request")
		}

		if want, got := option.Data, duid.Bytes(); !bytes.Equal(want, got) {
			t.Fatalf("unexpected client ID:\n- want: %v\n-  got: %v", want, got)
		}

		if want, got := int64(len(p)), r.Length; want != got {
			t.Fatalf("unexpected request length: %v != %v", want, got)
		}

		if want, got := addr.String(), r.RemoteAddr; want != got {
			t.Fatalf("unexpected remote address: %v != %v", want, got)
		}

		if want, got := p, r.packet; !bytes.Equal(want, got) {
			t.Fatalf("unexpected packet:\n- want: %v\n-  got: %v", want, got)
		}

		if _, err := w.Write(response); err != nil {
			t.Fatal(err)
		}
	})

	// Verify correct response from testServeConn
	if want, got := response, tc.buf; !bytes.Equal(want, got) {
		t.Fatalf("unexpected response:\n- want: %v\n-  got: %v", want, got)
	}
	if tc.cm != nil {
		t.Fatal("control message should be nil")
	}
	if want, got := addr, tc.addr; want != got {
		t.Fatalf("unexpected response address: %v != %v", want, got)
	}
}

// testServeConn implements serveConn, and allows DHCP responses without opening
// a network connection.
type testServeConn struct {
	buf  []byte
	cm   *ipv6.ControlMessage
	addr net.Addr
}

// WriteTo implements serveConn for testServeConn.
func (c *testServeConn) WriteTo(p []byte, cm *ipv6.ControlMessage, addr net.Addr) (int, error) {
	c.buf = make([]byte, len(p), len(p))
	copy(c.buf, p)
	c.cm = cm
	c.addr = addr

	return len(p), nil
}

// testConnServe sets up a Server, Handler, and conn for an input Packet and
// address.  Once setup is complete, it invokes function fn using conn.serve
// and returns the captured response data.
func testConnServe(t *testing.T, p Packet, addr *net.UDPAddr, fn func(Responser, *Request)) *testServeConn {
	mux := NewServeMux()
	mux.HandleFunc(p.MessageType(), fn)

	s := &Server{
		Handler: mux,
	}

	tc := &testServeConn{}

	c, err := s.newConn(tc, addr, len(p), p)
	if err != nil {
		t.Fatal(err)
	}

	c.serve()
	return tc
}
