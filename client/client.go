package client

import (
	"fmt"
	"net"
	"time"

	"github.com/mdlayher/dhcp6"
	"github.com/mdlayher/eui64"
	"golang.org/x/net/ipv6"
)

const (
	listenPort = 546
	dstPort    = 547
)

var (
	// All DHCP servers and relay agents on the local network segment (RFC 3315)
	// IPv6 Multicast (RFC 2464)
	// insert the low 32 Bits of the multicast IPv6 Address into the Ethernet Address (RFC 7042 2.3.1.)
	multicastMAC = net.HardwareAddr([]byte{0x33, 0x33, 0x00, 0x01, 0x00, 0x02})
)

type Client struct {
	// The HardwareAddr to send in the request.
	srcMAC net.HardwareAddr

	// Packet socket to send on.
	conn *ipv6.PacketConn

	// Max number of attempts to multicast DHCPv6 solicits.
	// -1 means infinity.
	retry int

	// Timeout for each Solicit try.
	timeout time.Duration
}

func New(haddr net.HardwareAddr, t time.Duration, r int) (*Client, error) {
	ip, err := eui64.ParseMAC(net.ParseIP("::"), haddr)
	if err != nil {
		return nil, err
	}

	// If this doesn't work like this, we may have to SO_BINDTODEVICE to
	// the interface. If that doesn't work... then we're back to raw
	// sockets. Hope not.
	c, err := net.ListenPacket("udp6", fmt.Sprintf("%s:%d", ip, listenPort))
	if err != nil {
		return nil, err
	}
	return &Client{
		srcMAC:  haddr,
		conn:    ipv6.NewPacketConn(c),
		timeout: t,
		retry:   r,
	}, nil
}

func (c *Client) Solicit() (*dhcp6.Packet, error) {
	solicitPacket, err := newSolicitPacket(c.srcMAC)
	if err != nil {
		return nil, fmt.Errorf("new solicit packet: %v", err)
	}

	var packet *dhcp6.Packet
	// Each retry takes the amount of timeout at worst.
	for i := 0; i < c.retry || c.retry < 0; i++ {
		if err := c.MulticastPacket(solicitPacket); err != nil {
			return nil, fmt.Errorf("sending solicit packet(%v) failed: %v", solicitPacket, err)
		}

		packet, err = c.ReadPacket()
		if err == nil {
			break
		}
	}

	return packet, nil
}

func (c *Client) MulticastPacket(p *dhcp6.Packet) error {
	ip, err := eui64.ParseMAC(net.ParseIP("::"), multicastMAC)
	if err != nil {
		return err
	}
	return c.SendPacket(p, ip)
}

func (c *Client) SendPacket(p *dhcp6.Packet, ip net.IP) error {
	pkt, err := p.MarshalBinary()
	if err != nil {
		return err
	}

	_, err = c.conn.WriteTo(pkt, nil, &net.UDPAddr{
		IP:   ip,
		Port: dstPort,
	})
	return err
}

func (c *Client) ReadPacket() (*dhcp6.Packet, error) {
	start := time.Now()

	for {
		deadline := time.Now().Add(c.timeout)
		remainingTime := deadline.Sub(start)
		if remainingTime <= 0 {
			return nil, fmt.Errorf("waiting for response timed out")
		}
		c.conn.SetReadDeadline(deadline)

		// TODO: What's a reasonable buffer size here? Depending on
		// what underlying syscall ReadFrom makes, maybe we want to
		// dynamically read more than 1500.
		b := make([]byte, 1500)
		n, _, _, err := c.conn.ReadFrom(b)
		if err != nil {
			continue
		}

		pkt := &dhcp6.Packet{}
		if err := pkt.UnmarshalBinary(b[:n]); err != nil {
			// Not a valid DHCPv6 reply; keep listening.
			continue
		}
		return pkt, nil
	}
}
