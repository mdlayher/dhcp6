package dhcp6

// MessageType represents a DHCP message type, as defined in IETF RFC 3315,
// Section 5.3.  Different DHCP message types are used to perform different
// actions between a client and server.
type MessageType uint8

// MessageType constants which indicate the message types described in IETF
// RFC 3315, Section 5.3.  Additional message types are defined in IANA's
// DHCPv6 parameters registry:
// http://www.iana.org/assignments/dhcpv6-parameters/dhcpv6-parameters.xhtml.
const (
	MessageTypeSolicit            MessageType = 1
	MessageTypeAdvertise          MessageType = 2
	MessageTypeRequest            MessageType = 3
	MessageTypeConfirm            MessageType = 4
	MessageTypeRenew              MessageType = 5
	MessageTypeRebind             MessageType = 6
	MessageTypeReply              MessageType = 7
	MessageTypeRelease            MessageType = 8
	MessageTypeDecline            MessageType = 9
	MessageTypeReconfigure        MessageType = 10
	MessageTypeInformationRequest MessageType = 11
	MessageTypeRelayForward       MessageType = 12
	MessageTypeRelayReply         MessageType = 13

	// BUG(mdlayher): add additional message types defined by IANA
)

// Status represesents a DHCP status code, as defined in IETF RFC 3315,
// Section 5.4.  Status codes are used to communicate success or failure
// between client and server.
type Status uint16

// Status constants which indicate the status codes described in IETF
// RFC 3315, Section 24.4.  Additional status are defined in IANA's
// DHCPv6 parameters registry:
// http://www.iana.org/assignments/dhcpv6-parameters/dhcpv6-parameters.xhtml.
const (
	StatusSuccess      Status = 0
	StatusUnspecFail   Status = 1
	StatusNoAddrsAvail Status = 2
	StatusNoBinding    Status = 3
	StatusNotOnLink    Status = 4
	StatusUseMulticast Status = 5

	// BUG(mdlayher): add additional status codes defined by IANA
)

// OptionCode represents a DHCP option, as defined in IETF RFC 3315,
// Section 22.  Options are used to carry additional information and
// parameters in DHCP messages between client and server.
type OptionCode uint16

// Status constants which indicate the option codes described in IETF
// RFC 3315, Section 24.3.  Additional option codes are defined in IANA's
// DHCPv6 parameters registry:
// http://www.iana.org/assignments/dhcpv6-parameters/dhcpv6-parameters.xhtml.
const (
	OptionClientID     OptionCode = 1
	OptionServerID     OptionCode = 2
	OptionIANA         OptionCode = 3
	OptionIATA         OptionCode = 4
	OptionIAAddr       OptionCode = 5
	OptionORO          OptionCode = 6
	OptionPreference   OptionCode = 7
	OptionElapsedTime  OptionCode = 8
	OptionRelayMsg     OptionCode = 9
	_                  OptionCode = 10
	OptionAuth         OptionCode = 11
	OptionUnicast      OptionCode = 12
	OptionStatusCode   OptionCode = 13
	OptionRapidCommit  OptionCode = 14
	OptionUserClass    OptionCode = 15
	OptionVendorClass  OptionCode = 16
	OptionVendorOpts   OptionCode = 17
	OptionInterfaceID  OptionCode = 18
	OptionReconfMsg    OptionCode = 19
	OptionReconfAccept OptionCode = 20

	// BUG(mdlayher): add additional message types defined by IANA
)
