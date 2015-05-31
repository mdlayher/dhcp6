package dhcp6test

import (
	"bytes"
	"testing"

	"github.com/mdlayher/dhcp6"
)

// TestRecorderBadTransactionID verifies that Recorder.Send returns an
// error when an invalid transaction ID is used.
func TestRecorderBadTransactionID(t *testing.T) {
	r := NewRecorder([]byte{0})

	if _, err := r.Send(dhcp6.MessageTypeAdvertise); err != dhcp6.ErrInvalidTransactionID {
		t.Fatalf("transaction ID is invalid, but got error: %v", err)
	}
}

// TestRecorderOK verifies that a Recorder properly captures information
// when a message is sent.
func TestRecorderOK(t *testing.T) {
	mt := dhcp6.MessageTypeAdvertise
	txID := []byte{0, 1, 2}
	clientID := []byte{0, 1}

	r := NewRecorder(txID)
	r.Options().AddRaw(dhcp6.OptionClientID, clientID)

	n, err := r.Send(mt)
	if err != nil {
		t.Fatal(err)
	}

	if want, got := len(r.Packet), n; want != got {
		t.Fatalf("unexpected packet length: %d != %d", want, got)
	}
	if want, got := mt, r.MessageType; want != got {
		t.Fatalf("unexpected message type: %v != %v", want, got)
	}
	if want, got := txID, r.TransactionID; !bytes.Equal(want, got) {
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
