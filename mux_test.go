package dhcp6

import (
	"bytes"
	"testing"
)

// TestServeMuxHandleNoReply verifies that ServeMux.Handle returns nothing
// when an unhandled message type is processed.
func TestServeMuxHandleNoReply(t *testing.T) {
	mux := NewServeMux()

	mt := MessageTypeAdvertise
	txID := []byte{0xf, 0x0, 0x0}

	p, err := newPacket(mt, txID, nil)
	if err != nil {
		t.Fatal(err)
	}

	req := newServerRequest(p, nil)
	buf := bytes.NewBuffer(nil)

	mux.ServeDHCP(buf, req)

	res := packet(buf.Bytes())
	if l := len(res); l > 0 {
		t.Fatalf("reply packet should be empty, but got length: %d", l)
	}
	if mt := res.MessageType(); mt != MessageType(0) {
		t.Fatalf("reply packet empty, but got message type: %v", mt)
	}
	if txID := res.TransactionID(); txID != nil {
		t.Fatalf("reply packet empty, but got transaction ID: %v", txID)
	}
}

// TestServeMuxHandleOK verifies that ServeMux.Handle properly accepts
// a struct that implements Handler.
func TestServeMuxHandleOK(t *testing.T) {
	mux := NewServeMux()

	mt := MessageTypeSolicit
	txID := []byte{0xf, 0x0, 0x0}

	mux.Handle(mt, &solicitHandler{})
	assertAdvertisePacket(t, mux, mt, txID)
}

// TestServeMuxHandleFunc verifies that ServeMux.HandleFunc properly accepts
// a normal function as a HandlerFunc.
func TestServeMuxHandleFunc(t *testing.T) {
	mux := NewServeMux()

	mt := MessageTypeSolicit
	txID := []byte{0xf, 0x0, 0x0}

	mux.HandleFunc(mt, solicit)
	assertAdvertisePacket(t, mux, mt, txID)
}

// assertAdvertisePacket checks for an Advertise packet in reply to a
// Solicit request, and verifies correct message type and transaction ID.
func assertAdvertisePacket(t *testing.T, mux *ServeMux, mt MessageType, txID []byte) {
	p, err := newPacket(mt, txID, nil)
	if err != nil {
		t.Fatal(err)
	}

	req := newServerRequest(p, nil)
	buf := bytes.NewBuffer(nil)

	mux.ServeDHCP(buf, req)

	res := packet(buf.Bytes())

	if want, got := MessageTypeAdvertise, res.MessageType(); want != got {
		t.Fatalf("unexpected reply message type: %v != %v", want, got)
	}
	if want, got := p.TransactionID(), res.TransactionID(); !bytes.Equal(want, got) {
		t.Fatalf("unexpected reply transaction ID: %v != %v", want, got)
	}
}

// solicitHandler is a Handler which returns an Advertise in reply
// to a Solicit request.
type solicitHandler struct{}

func (h *solicitHandler) ServeDHCP(w Responser, r *Request) {
	solicit(w, r)
}

// solicit is a function which can be adapted as a HandlerFunc.
func solicit(w Responser, r *Request) {
	p, err := newPacket(MessageTypeAdvertise, r.TransactionID, nil)
	if err != nil {
		panic(err)
	}

	w.Write(p)
}
