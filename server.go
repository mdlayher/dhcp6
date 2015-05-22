package dhcp6

import (
	"net"

	"golang.org/x/net/ipv6"
)

var (
	// AllRelayAgentsAndServersAddr is the multicast address group which is
	// used to communicate with neighboring (on-link) DHCP servers and relay
	// agents, as defined in IETF RFC 3315, Section 5.1.  All DHCP servers
	// and relay agents are members of this multicast group.
	AllRelayAgentsAndServersAddr = &net.IPAddr{
		IP: net.ParseIP("ff02::1:2"),
	}

	// AllServersAddr is the multicast address group which is used by a
	// DHCP relay agent to communicate with DHCP servers, if the relay agent
	// wishes to send messages to all servers, or does not know the unicast
	// address of a server.  All DHCP servers are members of this multicast
	// group.
	AllServersAddr = &net.IPAddr{
		IP: net.ParseIP("ff05::1:3"),
	}
)

// Server represents a DHCP server, and is used to configure a DHCP server's
// behavior.
type Server struct {
	// The name of the interface on which this server should listen.
	// Traffic from any other interface will be filtered out and
	// ignored by the server.
	Iface string

	// The handler to use while serving DHCP requests.  If this
	// value is nil, DefaultServeMux will be used.
	Handler Handler

	// Which IPv6 multicast groups this server will join on start-up.  Because
	// the default configuration acts as a DHCP server, most servers will
	// typically join both AllRelayAgentsAndServersAddr, and AllServersAddr.
	// If configuring a relay agent, only the former value should be used.
	MulticastGroups []*net.IPAddr

	ifIndex int
}

// ListenAndServe listens for UDP6 connections on port [::]:567 of the
// specified interface, using the default Server configuration and specified
// handler to handle DHCPv6 connections.  If the handler is nil,
// DefaultServeMux is used instead.
//
// In this configuration, the server acts as a DHCP server, but NOT as a
// DHCP relay agent.  For more information on DHCP relay agents, see
// IETF RFC 3315, Section 20.
func ListenAndServe(iface string, handler Handler) error {
	return (&Server{
		Iface:   iface,
		Handler: handler,
		MulticastGroups: []*net.IPAddr{
			AllRelayAgentsAndServersAddr,
			AllServersAddr,
		},
	}).ListenAndServe()
}

// ListenAndServe listens on the UDP6 [::]:547 using the interface defined in
// srv.Iface.  Traffic from any other interface will be filtered out and ignored.
// Serve is called to handle serving DHCP traffic once ListenAndServe opens a
// UDP6 packet connection, and joins the multicast groups defined in
// srv.MulticastGroups.
func (srv *Server) ListenAndServe() error {
	// Check for valid interface
	iface, err := net.InterfaceByName(srv.Iface)
	if err != nil {
		return err
	}

	// Open UDP6 packet connection listener on designated DHCPv6 port
	conn, err := net.ListenPacket("udp6", "[::]:547")
	if err != nil {
		return err
	}

	// Set up IPv6 packet connection
	p := ipv6.NewPacketConn(conn)

	// On return, handle leaving multicast groups and closing connection
	defer func() {
		for _, g := range srv.MulticastGroups {
			_ = p.LeaveGroup(iface, g)
		}

		_ = conn.Close()
	}()

	// Filter any traffic which does not indicate the interface
	// defined by srv.Iface.
	if err := p.SetControlMessage(ipv6.FlagInterface, true); err != nil {
		return err
	}

	// Join appropriate multicast groups
	for _, g := range srv.MulticastGroups {
		if err := p.JoinGroup(iface, g); err != nil {
			return err
		}
	}

	// Begin serving connections
	srv.ifIndex = iface.Index
	return srv.Serve(p)
}

// Serve accepts incoming connections on ipv6.PacketConn p, creating a
// new goroutine for each.  The service goroutine reads requests, filters
// any inappropriate ones, and then calls srv.Handler to handle them.
func (srv *Server) Serve(p *ipv6.PacketConn) error {
	defer p.Close()

	// Loop and read requests until exit
	buf := make([]byte, 1500)
	for {
		n, cm, addr, err := p.ReadFrom(buf)
		if err != nil {
			// BUG(mdlayher): determine if error can be temporary
			return err
		}

		// Filter any traffic with a control message indicating an incorrect
		// interface index
		if cm != nil && cm.IfIndex != srv.ifIndex {
			continue
		}

		// Create conn struct with data specific to this connection
		uc, err := srv.newConn(p, addr.(*net.UDPAddr), n, buf)
		if err != nil {
			continue
		}

		// Serve conn and continue looping for more connections
		go uc.serve()
	}
}

// conn represents an in-flight DHCP connection, and contains information about
// the connection and server.
type conn struct {
	remoteAddr *net.UDPAddr
	server     *Server
	p          *ipv6.PacketConn
	buf        []byte
}

// newConn creates a new conn using information received in a single DHCP
// connection.  newConn makes a copy of the input buffer for use in handling
// a single connection.
// BUG(mdlayher): consider using a sync.Pool with many buffers available to avoid
// allocating a new one on each connection
func (srv *Server) newConn(p *ipv6.PacketConn, addr *net.UDPAddr, n int, buf []byte) (*conn, error) {
	c := &conn{
		remoteAddr: addr,
		server:     srv,
		p:          p,
		buf:        make([]byte, n, n),
	}
	copy(c.buf, buf[:n])

	return c, nil
}

// response represents a DHCP response, and implements Responser so that
// outbound packets can be appropriately sent.
type response struct {
	remoteAddr *net.UDPAddr
	p          *ipv6.PacketConn
	req        *Request
}

// Write implements Responser, and writes a packet directly to the address
// indicated in the response.
func (r *response) Write(p []byte) (int, error) {
	return r.p.WriteTo(p, nil, r.remoteAddr)
}

// serve handles serving an individual DHCP connection, and is invoked in a
// goroutine.
func (c *conn) serve() {
	// Parse Packet data from raw buffer
	p := Packet(c.buf)

	// Set up Request with information from a Packet, providing a nicer
	// API for callers to implement their own DHCP request handlers
	r := newRequest(p, c.remoteAddr)

	// Set up response to send responses back to the original requester
	w := &response{
		remoteAddr: c.remoteAddr,
		p:          c.p,
		req:        r,
	}

	// If set, invoke DHCP handler using request and response
	// Default to DefaultServeMux if handler is not available
	handler := c.server.Handler
	if handler == nil {
		handler = DefaultServeMux
	}

	handler.ServeDHCP(w, r)
}
