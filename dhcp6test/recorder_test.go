package dhcp6test

import (
	"bytes"
	"testing"

	"github.com/mdlayher/dhcp6"
)

// TestRecorder verifies that a Recorder properly captures information
// when a message is sent.
func TestRecorder(t *testing.T) {
	mt := dhcp6.MessageTypeAdvertise
	txID := [3]byte{0, 1, 2}
	clientID := []byte{0, 1}

	r := NewRecorder(txID)
	r.Options().AddRaw(dhcp6.OptionClientID, clientID)

	if _, err := r.Send(mt); err != nil {
		t.Fatal(err)
	}

	if want, got := mt, r.MessageType; want != got {
		t.Fatalf("unexpected message type: %v != %v", want, got)
	}
	if want, got := txID[:], r.TransactionID[:]; !bytes.Equal(want, got) {
		t.Fatalf("unexpected transaction ID: %v != %v", want, got)
	}

	duid, ok, err := r.Options().ClientID()
	if err != nil || !ok {
		t.Fatal("empty or invalid client ID option")
	}
	if want, got := clientID, duid.Bytes(); !bytes.Equal(want, got) {
		t.Fatalf("unexpected client ID: %v != %v", want, got)
	}
}
