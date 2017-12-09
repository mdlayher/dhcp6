package client

import (
	"math/rand"
	"net"

	"github.com/mdlayher/dhcp6"
	"github.com/mdlayher/dhcp6/opts"
)

func newSolicitOptions(mac net.HardwareAddr) (dhcp6.Options, error) {
	options := make(dhcp6.Options)

	// TODO: This should be generated.
	id := [4]byte{'r', 'o', 'o', 't'}
	// IANA = requesting a non-temporary address.
	if err := options.Add(dhcp6.OptionIANA, opts.NewIANA(id, 0, 0, nil)); err != nil {
		return nil, err
	}
	// Request an immediate Reply with an IP instead of an Advertise packet.
	if err := options.Add(dhcp6.OptionRapidCommit, nil); err != nil {
		return nil, err
	}
	if err := options.Add(dhcp6.OptionElapsedTime, opts.ElapsedTime(0)); err != nil {
		return nil, err
	}

	oro := opts.OptionRequestOption{
		dhcp6.OptionDNSServers,
		dhcp6.OptionDomainList,
		dhcp6.OptionBootFileURL,
		dhcp6.OptionBootFileParam,
	}
	if err := options.Add(dhcp6.OptionORO, oro); err != nil {
		return nil, err
	}

	if err := options.Add(dhcp6.OptionClientID, opts.NewDUIDLL(6, mac)); err != nil {
		return nil, err
	}
	return options, nil
}

func newSolicitPacket(mac net.HardwareAddr) (*dhcp6.Packet, error) {
	options, err := newSolicitOptions(mac)
	if err != nil {
		return nil, err
	}

	p := &dhcp6.Packet{
		MessageType: dhcp6.MessageTypeSolicit,
		Options:     options,
	}
	rand.Read(p.TransactionID[:])
	return p, nil
}
