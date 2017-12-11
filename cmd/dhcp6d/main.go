// Command dhcp6d is an example DHCPv6 server.  It can only assign a
// single IPv6 address, and is not a complete DHCPv6 server implementation
// by any means.  It is meant to demonstrate usage of package dhcp6.
package main

import (
	"encoding/hex"
	"flag"
	"log"
	"net"
	"time"

	"github.com/mdlayher/dhcp6"
	"github.com/mdlayher/dhcp6/dhcp6opts"
	"github.com/mdlayher/dhcp6/server"
)

func main() {
	iface := flag.String("i", "eth0", "interface to serve DHCPv6")
	ipFlag := flag.String("ip", "", "IPv6 address to serve over DHCPv6")
	flag.Parse()

	// Only accept a single IPv6 address
	ip := net.ParseIP(*ipFlag).To16()
	if ip == nil || ip.To4() != nil {
		log.Fatal("IP is not an IPv6 address")
	}

	// Make Handler to assign ip and use handle for requests
	h := &Handler{
		ip:      ip,
		handler: handle,
	}

	// Bind DHCPv6 server to interface and use specified handler
	log.Printf("binding DHCPv6 server to interface %s...", *iface)
	if err := server.ListenAndServe(*iface, h); err != nil {
		log.Fatal(err)
	}
}

// A Handler is a basic DHCPv6 handler.
type Handler struct {
	ip      net.IP
	handler handler
}

// ServeDHCP is a dhcp6.Handler which invokes an internal handler that
// allows errors to be returned and handled in one place.
func (h *Handler) ServeDHCP(w server.ResponseSender, r *server.Request) {
	if err := h.handler(h.ip, w, r); err != nil {
		log.Println(err)
	}
}

// A handler is a DHCPv6 handler function which can assign a single IPv6
// address and also return an error.
type handler func(ip net.IP, w server.ResponseSender, r *server.Request) error

// handle is a handler which assigns IPv6 addresses using DHCPv6.
func handle(ip net.IP, w server.ResponseSender, r *server.Request) error {
	// Accept only Solicit, Request, or Confirm, since this server
	// does not handle Information Request or other message types
	valid := map[dhcp6.MessageType]struct{}{
		dhcp6.MessageTypeSolicit: {},
		dhcp6.MessageTypeRequest: {},
		dhcp6.MessageTypeConfirm: {},
	}
	if _, ok := valid[r.MessageType]; !ok {
		return nil
	}

	// Make sure client sent a client ID.
	duid, err := r.Options.GetOne(dhcp6.OptionClientID)
	if err != nil {
		return nil
	}

	// Log information about the incoming request.
	log.Printf("[%s] id: %s, type: %d, len: %d, tx: %s",
		hex.EncodeToString(duid),
		r.RemoteAddr,
		r.MessageType,
		r.Length,
		hex.EncodeToString(r.TransactionID[:]),
	)

	// Print out options the client has requested
	if opts, err := dhcp6opts.GetOptionRequest(r.Options); err == nil {
		log.Println("\t- requested:")
		for _, o := range opts {
			log.Printf("\t\t - %s", o)
		}
	}

	// Client must send a IANA to retrieve an IPv6 address
	ianas, err := dhcp6opts.GetIANA(r.Options)
	if err == dhcp6.ErrOptionNotPresent {
		log.Println("no IANAs provided")
		return nil
	}
	if err != nil {
		return err
	}

	// Only accept one IANA
	if len(ianas) > 1 {
		log.Println("can only handle one IANA")
		return nil
	}
	ia := ianas[0]

	log.Printf("\tIANA: %s (%s, %s), opts: %v",
		hex.EncodeToString(ia.IAID[:]),
		ia.T1,
		ia.T2,
		ia.Options,
	)

	// Instruct client to prefer this server unconditionally
	_ = w.Options().Add(dhcp6.OptionPreference, dhcp6opts.Preference(255))

	// IANA may already have an IAAddr if an address was already assigned.
	// If not, assign a new one.
	iaaddrs, err := dhcp6opts.GetIAAddr(ia.Options)
	switch err {
	case dhcp6.ErrOptionNotPresent:
		// Client did not indicate a previous address, and is soliciting.
		// Advertise a new IPv6 address.
		if r.MessageType == dhcp6.MessageTypeSolicit {
			return newIAAddr(ia, ip, w, r)
		}
		// Client did not indicate an address and is not soliciting.  Ignore.
		return nil

	case nil:
		// Fall through below.

	default:
		return err
	}

	// Confirm or renew an existing IPv6 address

	// Must have an IAAddr, but we ignore if more than one is present
	if len(iaaddrs) == 0 {
		return nil
	}
	iaa := iaaddrs[0]

	log.Printf("\t\tIAAddr: %s (%s, %s), opts: %v",
		iaa.IP,
		iaa.PreferredLifetime,
		iaa.ValidLifetime,
		iaa.Options,
	)

	// Add IAAddr inside IANA, add IANA to options
	_ = ia.Options.Add(dhcp6.OptionIAAddr, iaa)
	_ = w.Options().Add(dhcp6.OptionIANA, ia)

	// Send reply to client
	_, err = w.Send(dhcp6.MessageTypeReply)
	return err
}

// newIAAddr creates a IAAddr for a IANA using the specified IPv6 address,
// and advertises it to a client.
func newIAAddr(ia *dhcp6opts.IANA, ip net.IP, w server.ResponseSender, r *server.Request) error {
	// Send IPv6 address with 60 second preferred lifetime,
	// 90 second valid lifetime, no extra options
	iaaddr, err := dhcp6opts.NewIAAddr(ip, 60*time.Second, 90*time.Second, nil)
	if err != nil {
		return err
	}

	// Add IAAddr inside IANA, add IANA to options
	_ = ia.Options.Add(dhcp6.OptionIAAddr, iaaddr)
	_ = w.Options().Add(dhcp6.OptionIANA, ia)

	// Advertise address to soliciting clients
	log.Printf("advertising IP: %s", ip)
	_, err = w.Send(dhcp6.MessageTypeAdvertise)
	return err
}
