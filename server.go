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
	// Iface is the name of the network interface on which this server should
	// listen.  Traffic from any other network interface will be filtered out
	// and ignored by the server.
	Iface string

	// Addr is the network address which this server should bind to.  The
	// default value is [::]:547, as specified in IETF RFC 3315, Section 5.2.
	Addr string

	// Handler is the handler to use while serving DHCP requests.  If this
	// value is nil, DefaultServeMux will be used in place of Handler.
	Handler Handler

	// MulticastGroups designates which IPv6 multicast groups this server
	// will join on start-up.  Because the default configuration acts as a
	// DHCP server, most servers will typically join both
	// AllRelayAgentsAndServersAddr, and AllServersAddr. If configuring a
	// DHCP relay agent, only the former value should be used.
	MulticastGroups []*net.IPAddr

	// ServerID is the the server's DUID, which uniquely identifies this
	// server to clients.  If no DUID is specified, a DUID-LL will be
	// generated using Iface's hardware type and address.  If possible,
	// servers with persistent storage available should generate a DUID-LLT
	// and store it for future use.
	ServerID DUID

	// ifIndex stores the index of Iface, which is used to filter out traffic
	// bound for other interfaces on this machine.
	ifIndex int
}

// ListenAndServe listens for UDP6 connections on the specified address of the
// specified interface, using the default Server configuration and specified
// handler to handle DHCPv6 connections.  If the handler is nil,
// DefaultServeMux is used instead.
//
// Any traffic which reaches the Server, and is not bound for the specified
// network interface, will be filtered out and ignored.
//
// In this configuration, the server acts as a DHCP server, but NOT as a
// DHCP relay agent.  For more information on DHCP relay agents, see
// IETF RFC 3315, Section 20.
func ListenAndServe(iface string, handler Handler) error {
	return (&Server{
		Iface:   iface,
		Addr:    "[::]:547",
		Handler: handler,
		MulticastGroups: []*net.IPAddr{
			AllRelayAgentsAndServersAddr,
			AllServersAddr,
		},
	}).ListenAndServe()
}

// ListenAndServe listens on the address specified by s.Addr using the network
// interface defined in s.Iface.  Traffic from any other interface will be
// filtered out and ignored.  Serve is called to handle serving DHCP traffic
// once ListenAndServe opens a UDP6 packet connection, and joins the multicast
// groups defined in s.MulticastGroups.
func (s *Server) ListenAndServe() error {
	// Check for valid interface
	iface, err := net.InterfaceByName(s.Iface)
	if err != nil {
		return err
	}

	// If no DUID was set for server previously, generate a DUID-LL
	// now using the interface's hardware type and address
	if s.ServerID == nil {
		// BUG(mdlayher): see if hardware type can be easily determined for
		// an interface.  For now, default to Ethernet (10mb) as defined here:
		// http://www.iana.org/assignments/arp-parameters/arp-parameters.xhtml.
		const ethernet10Mb = 1
		s.ServerID = NewDUIDLL(ethernet10Mb, iface.HardwareAddr)
	}

	// Open UDP6 packet connection listener on specified address
	conn, err := net.ListenPacket("udp6", s.Addr)
	if err != nil {
		return err
	}

	// Set up IPv6 packet connection, and on return, handle leaving multicast
	// groups and closing connection
	p := ipv6.NewPacketConn(conn)
	defer func() {
		for _, g := range s.MulticastGroups {
			_ = p.LeaveGroup(iface, g)
		}

		_ = conn.Close()
	}()

	// Filter any traffic which does not indicate the interface
	// defined by s.Iface.
	if err := p.SetControlMessage(ipv6.FlagInterface, true); err != nil {
		return err
	}

	// Join appropriate multicast groups
	for _, g := range s.MulticastGroups {
		if err := p.JoinGroup(iface, g); err != nil {
			return err
		}
	}

	// Begin serving connections
	s.ifIndex = iface.Index
	return s.Serve(p)
}

// Serve accepts incoming connections on ipv6.PacketConn p, creating a
// new goroutine for each.  The service goroutine reads requests, generates
// the appropriate Request and Responser values, then calls s.Handler to handle
// the request.
func (s *Server) Serve(p *ipv6.PacketConn) error {
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
		if cm != nil && cm.IfIndex != s.ifIndex {
			continue
		}

		// Create conn struct with data specific to this connection
		uc, err := s.newConn(p, addr.(*net.UDPAddr), n, buf)
		if err != nil {
			continue
		}

		// Serve conn and continue looping for more connections
		go uc.serve()
	}
}

// serveConn is an internal type which allows a packet connection to be swapped
// out for testing, without opening a network connection.
type serveConn interface {
	WriteTo([]byte, *ipv6.ControlMessage, net.Addr) (int, error)
}

// conn represents an in-flight DHCP connection, and contains information about
// the connection and server.
type conn struct {
	remoteAddr *net.UDPAddr
	server     *Server
	conn       serveConn
	buf        []byte
}

// newConn creates a new conn using information received in a single DHCP
// connection.  newConn makes a copy of the input buffer for use in handling
// a single connection.
// BUG(mdlayher): consider using a sync.Pool with many buffers available to avoid
// allocating a new one on each connection
func (s *Server) newConn(p serveConn, addr *net.UDPAddr, n int, buf []byte) (*conn, error) {
	c := &conn{
		remoteAddr: addr,
		server:     s,
		conn:       p,
		buf:        make([]byte, n, n),
	}
	copy(c.buf, buf[:n])

	return c, nil
}

// response represents a DHCP response, and implements Responser so that
// outbound packets can be appropriately sent.
type response struct {
	remoteAddr *net.UDPAddr
	conn       serveConn
	req        *Request
}

// Write implements Responser, and writes a packet directly to the address
// indicated in the response.
func (r *response) Write(p []byte) (int, error) {
	return r.conn.WriteTo(p, nil, r.remoteAddr)
}

// serve handles serving an individual DHCP connection, and is invoked in a
// goroutine.
func (c *conn) serve() {
	// Parse packet data from raw buffer
	p := packet(c.buf)

	// Set up Request with information from a packet, providing a nicer
	// API for callers to implement their own DHCP request handlers
	r := newServerRequest(p, c.remoteAddr)

	// Set up response to send responses back to the original requester
	w := &response{
		remoteAddr: c.remoteAddr,
		conn:       c.conn,
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
