package dhcp6

import (
	"bytes"
	"net"
	"reflect"
	"testing"
	"time"
)

// TestOptionsAdd verifies that Options.Add correctly creates or appends
// OptionCode keys with Byteser values to an Options map.
func TestOptionsAdd(t *testing.T) {
	var tests = []struct {
		description string
		code        OptionCode
		byteser     Byteser
		options     Options
	}{
		{
			description: "DUID-LLT",
			code:        OptionClientID,
			byteser: &DUIDLLT{
				Type:         DUIDTypeLLT,
				HardwareType: 1,
				Time:         duidLLTTime.Add(1 * time.Minute).Sub(duidLLTTime),
				HardwareAddr: net.HardwareAddr([]byte{0, 1, 0, 1, 0, 1}),
			},
			options: Options{
				OptionClientID: [][]byte{{
					0, 1,
					0, 1,
					0, 0, 0, 60,
					0, 1, 0, 1, 0, 1,
				}},
			},
		},
		{
			description: "DUID-EN",
			code:        OptionClientID,
			byteser: &DUIDEN{
				Type:             DUIDTypeEN,
				EnterpriseNumber: 100,
				Identifier:       []byte{0, 1, 2, 3, 4},
			},
			options: Options{
				OptionClientID: [][]byte{{
					0, 2,
					0, 0, 0, 100,
					0, 1, 2, 3, 4,
				}},
			},
		},
		{
			description: "DUID-LL",
			code:        OptionClientID,
			byteser: &DUIDLL{
				Type:         DUIDTypeLL,
				HardwareType: 1,
				HardwareAddr: net.HardwareAddr([]byte{0, 1, 0, 1, 0, 1}),
			},
			options: Options{
				OptionClientID: [][]byte{{
					0, 3,
					0, 1,
					0, 1, 0, 1, 0, 1,
				}},
			},
		},
		{
			description: "DUID-UUID",
			code:        OptionClientID,
			byteser: &DUIDUUID{
				Type: DUIDTypeUUID,
				UUID: [16]byte{
					1, 1, 1, 1,
					2, 2, 2, 2,
					3, 3, 3, 3,
					4, 4, 4, 4,
				},
			},
			options: Options{
				OptionClientID: [][]byte{{
					0, 4,
					1, 1, 1, 1,
					2, 2, 2, 2,
					3, 3, 3, 3,
					4, 4, 4, 4,
				}},
			},
		},
		{
			description: "IA_NA",
			code:        OptionIANA,
			byteser: &IANA{
				IAID: [4]byte{0, 1, 2, 3},
				T1:   30 * time.Second,
				T2:   60 * time.Second,
			},
			options: Options{
				OptionIANA: [][]byte{{
					0, 1, 2, 3,
					0, 0, 0, 30,
					0, 0, 0, 60,
				}},
			},
		},
		{
			description: "IA_TA",
			code:        OptionIATA,
			byteser: &IATA{
				IAID: [4]byte{0, 1, 2, 3},
			},
			options: Options{
				OptionIATA: [][]byte{{
					0, 1, 2, 3,
				}},
			},
		},
		{
			description: "IAAddr",
			code:        OptionIAAddr,
			byteser: &IAAddr{
				IP:                net.IPv6loopback,
				PreferredLifetime: 30 * time.Second,
				ValidLifetime:     60 * time.Second,
			},
			options: Options{
				OptionIAAddr: [][]byte{{
					0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
					0, 0, 0, 30,
					0, 0, 0, 60,
				}},
			},
		},
		{
			description: "StatusCode",
			code:        OptionStatusCode,
			byteser: &StatusCode{
				Code:    StatusSuccess,
				Message: "hello world",
			},
			options: Options{
				OptionStatusCode: [][]byte{{
					0, 0,
					'h', 'e', 'l', 'l', 'o', ' ', 'w', 'o', 'r', 'l', 'd',
				}},
			},
		},
	}

	for i, tt := range tests {
		o := make(Options)
		o.Add(tt.code, tt.byteser)

		if want, got := tt.options, o; !reflect.DeepEqual(want, got) {
			t.Fatalf("[%02d] test %q, unexpected Options map:\n- want: %v\n-  got: %v",
				i, tt.description, want, got)
		}
	}
}

// TestOptionsAdd verifies that Options.AddRaw correctly creates or appends
// key/value Option pairs to an Options map.
func TestOptionsAddRaw(t *testing.T) {
	var tests = []struct {
		description string
		kv          []option
		options     Options
	}{
		{
			description: "one key/value pair",
			kv: []option{
				{
					Code: 1,
					Data: []byte("foo"),
				},
			},
			options: Options{
				1: [][]byte{[]byte("foo")},
			},
		},
		{
			description: "two key/value pairs",
			kv: []option{
				{
					Code: 1,
					Data: []byte("foo"),
				},
				{
					Code: 2,
					Data: []byte("bar"),
				},
			},
			options: Options{
				1: [][]byte{[]byte("foo")},
				2: [][]byte{[]byte("bar")},
			},
		},
		{
			description: "three key/value pairs, two with same key",
			kv: []option{
				{
					Code: 1,
					Data: []byte("foo"),
				},
				{
					Code: 1,
					Data: []byte("baz"),
				},
				{
					Code: 2,
					Data: []byte("bar"),
				},
			},
			options: Options{
				1: [][]byte{[]byte("foo"), []byte("baz")},
				2: [][]byte{[]byte("bar")},
			},
		},
	}

	for i, tt := range tests {
		o := make(Options)
		for _, p := range tt.kv {
			o.AddRaw(p.Code, p.Data)
		}

		if want, got := tt.options, o; !reflect.DeepEqual(want, got) {
			t.Fatalf("[%02d] test %q, unexpected Options map:\n- want: %v\n-  got: %v",
				i, tt.description, want, got)
		}
	}
}

// TestOptionsGet verifies that Options.Get correctly selects the first value
// for a given key, if the value is not empty in an Options map.
func TestOptionsGet(t *testing.T) {
	var tests = []struct {
		description string
		options     Options
		key         OptionCode
		value       []byte
		ok          bool
	}{
		{
			description: "nil Options map",
		},
		{
			description: "empty Options map",
			options:     Options{},
		},
		{
			description: "value not present in Options map",
			options: Options{
				2: [][]byte{[]byte("foo")},
			},
			key: 1,
		},
		{
			description: "value present in Options map, but zero length value for key",
			options: Options{
				1: [][]byte{},
			},
			key: 1,
			ok:  true,
		},
		{
			description: "value present in Options map",
			options: Options{
				1: [][]byte{[]byte("foo")},
			},
			key:   1,
			value: []byte("foo"),
			ok:    true,
		},
		{
			description: "value present in Options map, with multiple values",
			options: Options{
				1: [][]byte{[]byte("foo"), []byte("bar")},
			},
			key:   1,
			value: []byte("foo"),
			ok:    true,
		},
	}

	for i, tt := range tests {
		value, ok := tt.options.Get(tt.key)

		if want, got := tt.value, value; !bytes.Equal(want, got) {
			t.Fatalf("[%02d] test %q, unexpected value for Options.Get(%v):\n- want: %v\n-  got: %v",
				i, tt.description, tt.key, want, got)
		}

		if want, got := tt.ok, ok; want != got {
			t.Fatalf("[%02d] test %q, unexpected ok for Options.Get(%v): %v != %v",
				i, tt.description, tt.key, want, got)
		}
	}
}

// TestOptionsClientID verifies that Options.ClientID properly parses and returns
// a DUID value, if one is available with OptionClientID.
func TestOptionsClientID(t *testing.T) {
	var tests = []struct {
		description string
		options     Options
		duid        DUID
		ok          bool
	}{
		{
			description: "OptionClientID not present in Options map",
		},
		{
			description: "OptionClientID present in Options map",
			options: Options{
				OptionClientID: [][]byte{{
					0, 3,
					0, 1,
					0, 1, 0, 1, 0, 1,
				}},
			},
			duid: &DUIDLL{
				Type:         DUIDTypeLL,
				HardwareType: 1,
				HardwareAddr: []byte{0, 1, 0, 1, 0, 1},
			},
			ok: true,
		},
	}

	for i, tt := range tests {
		// DUID parsing is tested elsewhere, so errors should automatically fail
		// test here
		duid, ok, err := tt.options.ClientID()
		if err != nil {
			t.Fatal(err)
		}

		if want, got := tt.duid, duid; !reflect.DeepEqual(want, got) {
			t.Fatalf("[%02d] test %q, unexpected value for Options.ClientID():\n- want: %v\n-  got: %v",
				i, tt.description, want, got)
		}

		if want, got := tt.ok, ok; want != got {
			t.Fatalf("[%02d] test %q, unexpected ok for Options.ClientID(): %v != %v",
				i, tt.description, want, got)
		}
	}
}

// TestOptionsServerID verifies that Options.ServerID properly parses and returns
// a DUID value, if one is available with OptionServerID.
func TestOptionsServerID(t *testing.T) {
	var tests = []struct {
		description string
		options     Options
		duid        DUID
		ok          bool
	}{
		{
			description: "OptionServerID not present in Options map",
		},
		{
			description: "OptionServerID present in Options map",
			options: Options{
				OptionServerID: [][]byte{{
					0, 3,
					0, 1,
					0, 1, 0, 1, 0, 1,
				}},
			},
			duid: &DUIDLL{
				Type:         DUIDTypeLL,
				HardwareType: 1,
				HardwareAddr: []byte{0, 1, 0, 1, 0, 1},
			},
			ok: true,
		},
	}

	for i, tt := range tests {
		// DUID parsing is tested elsewhere, so errors should automatically fail
		// test here
		duid, ok, err := tt.options.ServerID()
		if err != nil {
			t.Fatal(err)
		}

		if want, got := tt.duid, duid; !reflect.DeepEqual(want, got) {
			t.Fatalf("[%02d] test %q, unexpected value for Options.ServerID():\n- want: %v\n-  got: %v",
				i, tt.description, want, got)
		}

		if want, got := tt.ok, ok; want != got {
			t.Fatalf("[%02d] test %q, unexpected ok for Options.ServerID(): %v != %v",
				i, tt.description, want, got)
		}
	}
}

// TestOptionsIANA verifies that Options.IANA properly parses and
// returns multiple IANA values, if one or more are available with OptionIANA.
func TestOptionsIANA(t *testing.T) {
	var tests = []struct {
		description string
		options     Options
		iana        []*IANA
		ok          bool
		err         error
	}{
		{
			description: "OptionIANA not present in Options map",
		},
		{
			description: "OptionIANA present in Options map, but too short",
			options: Options{
				OptionIANA: [][]byte{bytes.Repeat([]byte{0}, 11)},
			},
			err: errInvalidIANA,
		},
		{
			description: "one OptionIANA present in Options map",
			options: Options{
				OptionIANA: [][]byte{{
					1, 2, 3, 4,
					0, 0, 0, 30,
					0, 0, 0, 60,
				}},
			},
			iana: []*IANA{
				{
					IAID: [4]byte{1, 2, 3, 4},
					T1:   30 * time.Second,
					T2:   60 * time.Second,
				},
			},
			ok: true,
		},
		{
			description: "two OptionIANA present in Options map",
			options: Options{
				OptionIANA: [][]byte{
					append(bytes.Repeat([]byte{0}, 12), []byte{0, 1, 0, 1, 1}...),
					append(bytes.Repeat([]byte{0}, 12), []byte{0, 2, 0, 1, 2}...),
				},
			},
			iana: []*IANA{
				{
					Options: Options{
						OptionClientID: [][]byte{{1}},
					},
				},
				{
					Options: Options{
						OptionServerID: [][]byte{{2}},
					},
				},
			},
			ok: true,
		},
	}

	for i, tt := range tests {
		iana, ok, err := tt.options.IANA()
		if err != nil {
			if want, got := tt.err, err; want != got {
				t.Fatalf("[%02d] test %q, unexpected error for Options.IANA: %v != %v",
					i, tt.description, want, got)
			}

			continue
		}

		for j := range tt.iana {
			if want, got := tt.iana[j].Bytes(), iana[j].Bytes(); !bytes.Equal(want, got) {
				t.Fatalf("[%02d:%02d] test %q, unexpected value for Options.IANA():\n- want: %v\n-  got: %v",
					i, j, tt.description, want, got)
			}
		}

		if want, got := tt.ok, ok; want != got {
			t.Fatalf("[%02d] test %q, unexpected ok for Options.IANA(): %v != %v",
				i, tt.description, want, got)
		}
	}
}

// TestOptionsIATA verifies that Options.IATA properly parses and
// returns multiple IATA values, if one or more are available with OptionIATA.
func TestOptionsIATA(t *testing.T) {
	var tests = []struct {
		description string
		options     Options
		iata        []*IATA
		ok          bool
		err         error
	}{
		{
			description: "OptionIATA not present in Options map",
		},
		{
			description: "OptionIATA present in Options map, but too short",
			options: Options{
				OptionIATA: [][]byte{{0, 0, 0}},
			},
			err: errInvalidIATA,
		},
		{
			description: "one OptionIATA present in Options map",
			options: Options{
				OptionIATA: [][]byte{{
					1, 2, 3, 4,
				}},
			},
			iata: []*IATA{
				{
					IAID: [4]byte{1, 2, 3, 4},
				},
			},
			ok: true,
		},
		{
			description: "two OptionIATA present in Options map",
			options: Options{
				OptionIATA: [][]byte{
					[]byte{0, 1, 2, 3, 0, 1, 0, 1, 1},
					[]byte{4, 5, 6, 7, 0, 2, 0, 1, 2},
				},
			},
			iata: []*IATA{
				{
					IAID: [4]byte{0, 1, 2, 3},
					Options: Options{
						OptionClientID: [][]byte{{1}},
					},
				},
				{
					IAID: [4]byte{4, 5, 6, 7},
					Options: Options{
						OptionServerID: [][]byte{{2}},
					},
				},
			},
			ok: true,
		},
	}

	for i, tt := range tests {
		iata, ok, err := tt.options.IATA()
		if err != nil {
			if want, got := tt.err, err; want != got {
				t.Fatalf("[%02d] test %q, unexpected error for Options.IATA: %v != %v",
					i, tt.description, want, got)
			}

			continue
		}

		for j := range tt.iata {
			if want, got := tt.iata[j].Bytes(), iata[j].Bytes(); !bytes.Equal(want, got) {
				t.Fatalf("[%02d:%02d] test %q, unexpected value for Options.IATA():\n- want: %v\n-  got: %v",
					i, j, tt.description, want, got)
			}
		}

		if want, got := tt.ok, ok; want != got {
			t.Fatalf("[%02d] test %q, unexpected ok for Options.IATA(): %v != %v",
				i, tt.description, want, got)
		}
	}
}

// TestOptionsIAAddr verifies that Options.IAAddr properly parses and
// returns multiple IAAddr values, if one or more are available with
// OptionIAAddr.
func TestOptionsIAAddr(t *testing.T) {
	var tests = []struct {
		description string
		options     Options
		iaaddr      []*IAAddr
		ok          bool
		err         error
	}{
		{
			description: "OptionIAAddr not present in Options map",
		},
		{
			description: "OptionIAAddr present in Options map, but too short",
			options: Options{
				OptionIAAddr: [][]byte{bytes.Repeat([]byte{0}, 23)},
			},
			err: errInvalidIAAddr,
		},
		{
			description: "one OptionIAAddr present in Options map",
			options: Options{
				OptionIAAddr: [][]byte{{
					0, 0, 0, 0,
					1, 1, 1, 1,
					2, 2, 2, 2,
					3, 3, 3, 3,
					0, 0, 0, 30,
					0, 0, 0, 60,
				}},
			},
			iaaddr: []*IAAddr{
				{
					IP: net.IP{
						0, 0, 0, 0,
						1, 1, 1, 1,
						2, 2, 2, 2,
						3, 3, 3, 3,
					},
					PreferredLifetime: 30 * time.Second,
					ValidLifetime:     60 * time.Second,
				},
			},
			ok: true,
		},
		{
			description: "two OptionIAAddr present in Options map",
			options: Options{
				OptionIAAddr: [][]byte{
					bytes.Repeat([]byte{0}, 24),
					bytes.Repeat([]byte{0}, 24),
				},
			},
			iaaddr: []*IAAddr{
				{
					IP: net.IPv6zero,
				},
				{
					IP: net.IPv6zero,
				},
			},
			ok: true,
		},
	}

	for i, tt := range tests {
		iaaddr, ok, err := tt.options.IAAddr()
		if err != nil {
			if want, got := tt.err, err; want != got {
				t.Fatalf("[%02d] test %q, unexpected error for Options.IAAddr: %v != %v",
					i, tt.description, want, got)
			}

			continue
		}

		for j := range tt.iaaddr {
			if want, got := tt.iaaddr[j].Bytes(), iaaddr[j].Bytes(); !bytes.Equal(want, got) {
				t.Fatalf("[%02d:%02d] test %q, unexpected value for Options.IAAddr():\n- want: %v\n-  got: %v",
					i, j, tt.description, want, got)
			}
		}

		if want, got := tt.ok, ok; want != got {
			t.Fatalf("[%02d] test %q, unexpected ok for Options.IAAddr(): %v != %v",
				i, tt.description, want, got)
		}
	}
}

// TestOptionsOptionRequest verifies that Options.OptionRequest properly parses
// and returns a slice of OptionCode values, if they are available with
// OptionORO.
func TestOptionsOptionRequest(t *testing.T) {
	var tests = []struct {
		description string
		options     Options
		codes       []OptionCode
		ok          bool
		err         error
	}{
		{
			description: "OptionORO not present in Options map",
		},
		{
			description: "OptionORO present in Options map, but not even length",
			options: Options{
				OptionORO: [][]byte{{0}},
			},
			err: errInvalidOptionRequest,
		},
		{
			description: "OptionORO present in Options map",
			options: Options{
				OptionORO: [][]byte{{0, 1}},
			},
			codes: []OptionCode{1},
			ok:    true,
		},
		{
			description: "OptionORO present in Options map, with multiple values",
			options: Options{
				OptionORO: [][]byte{{0, 1, 0, 2, 0, 3}},
			},
			codes: []OptionCode{1, 2, 3},
			ok:    true,
		},
	}

	for i, tt := range tests {
		codes, ok, err := tt.options.OptionRequest()
		if err != nil {
			if want, got := tt.err, err; want != got {
				t.Fatalf("[%02d] test %q, unexpected error for Options.OptionRequest(): %v != %v",
					i, tt.description, want, got)
			}

			continue
		}

		if want, got := tt.codes, codes; !reflect.DeepEqual(want, got) {
			t.Fatalf("[%02d] test %q, unexpected value for Options.OptionRequest():\n- want: %v\n-  got: %v",
				i, tt.description, want, got)
		}

		if want, got := tt.ok, ok; want != got {
			t.Fatalf("[%02d] test %q, unexpected ok for Options.OptionRequest(): %v != %v",
				i, tt.description, want, got)
		}
	}
}

// TestOptionsPreference verifies that Options.Preference properly parses
// and returns an integer value, if it is available with OptionPreference.
func TestOptionsPreference(t *testing.T) {
	var tests = []struct {
		description string
		options     Options
		preference  uint8
		ok          bool
		err         error
	}{
		{
			description: "OptionPreference not present in Options map",
		},
		{
			description: "OptionPreference present in Options map, but too short length",
			options: Options{
				OptionPreference: [][]byte{{}},
			},
			err: errInvalidPreference,
		},
		{
			description: "OptionPreference present in Options map, but too long length",
			options: Options{
				OptionPreference: [][]byte{{0, 1}},
			},
			err: errInvalidPreference,
		},
		{
			description: "OptionPreference present in Options map",
			options: Options{
				OptionPreference: [][]byte{{255}},
			},
			preference: 255,
			ok:         true,
		},
	}

	for i, tt := range tests {
		preference, ok, err := tt.options.Preference()
		if err != nil {
			if want, got := tt.err, err; want != got {
				t.Fatalf("[%02d] test %q, unexpected error for Options.Preference(): %v != %v",
					i, tt.description, want, got)
			}

			continue
		}

		if want, got := tt.preference, preference; want != got {
			t.Fatalf("[%02d] test %q, unexpected value for Options.Preference(): %v != %v",
				i, tt.description, want, got)
		}

		if want, got := tt.ok, ok; want != got {
			t.Fatalf("[%02d] test %q, unexpected ok for Options.Preference(): %v != %v",
				i, tt.description, want, got)
		}
	}
}

// TestOptionsUnicast verifies that Options.Unicast properly parses
// and returns an IPv6 address or an error, if available with OptionUnicast.
func TestOptionsUnicast(t *testing.T) {
	var tests = []struct {
		description string
		options     Options
		ip          net.IP
		ok          bool
		err         error
	}{
		{
			description: "OptionUnicast not present in Options map",
		},
		{
			description: "OptionUnicast present in Options map, but too short length",
			options: Options{
				OptionUnicast: [][]byte{bytes.Repeat([]byte{0}, 15)},
			},
			err: errInvalidUnicast,
		},
		{
			description: "OptionUnicast present in Options map, but too long length",
			options: Options{
				OptionUnicast: [][]byte{bytes.Repeat([]byte{0}, 17)},
			},
			err: errInvalidUnicast,
		},
		{
			description: "OptionUnicast present in Options map with IPv4 address",
			options: Options{
				OptionUnicast: [][]byte{net.IPv4(192, 168, 1, 1)},
			},
			err: errInvalidUnicast,
		},
		{
			description: "OptionUnicast present in Options map with IPv6 address",
			options: Options{
				OptionUnicast: [][]byte{net.IPv6loopback},
			},
			ip: net.IPv6loopback,
			ok: true,
		},
	}

	for i, tt := range tests {
		ip, ok, err := tt.options.Unicast()
		if err != nil {
			if want, got := tt.err, err; want != got {
				t.Fatalf("[%02d] test %q, unexpected error for Options.Unicast(): %v != %v",
					i, tt.description, want, got)
			}

			continue
		}

		if want, got := tt.ip, ip; !bytes.Equal(want, got) {
			t.Fatalf("[%02d] test %q, unexpected value for Options.Unicast():\n- want: %v\n-  got: %v",
				i, tt.description, want, got)
		}

		if want, got := tt.ok, ok; want != got {
			t.Fatalf("[%02d] test %q, unexpected ok for Options.Unicast(): %v != %v",
				i, tt.description, want, got)
		}
	}
}

// TestOptionsStatusCode verifies that Options.StatusCode properly parses
// and returns a StatusCode value, if it is available with OptionStatusCode.
func TestOptionsStatusCode(t *testing.T) {
	var tests = []struct {
		description string
		options     Options
		sc          *StatusCode
		ok          bool
		err         error
	}{
		{
			description: "OptionStatusCode not present in Options map",
		},
		{
			description: "OptionStatusCode present in Options map, but too short length",
			options: Options{
				OptionStatusCode: [][]byte{{}},
			},
			err: errInvalidStatusCode,
		},
		{
			description: "OptionStatusCode present in Options map, no message",
			options: Options{
				OptionStatusCode: [][]byte{{0, 0}},
			},
			sc: &StatusCode{
				Code: StatusSuccess,
			},
			ok: true,
		},
		{
			description: "OptionStatusCode present in Options map, with message",
			options: Options{
				OptionStatusCode: [][]byte{append([]byte{0, 0}, []byte("deadbeef")...)},
			},
			sc: &StatusCode{
				Code:    StatusSuccess,
				Message: "deadbeef",
			},
			ok: true,
		},
	}

	for i, tt := range tests {
		sc, ok, err := tt.options.StatusCode()
		if err != nil {
			if want, got := tt.err, err; want != got {
				t.Fatalf("[%02d] test %q, unexpected error for Options.StatusCode(): %v != %v",
					i, tt.description, want, got)
			}

			continue
		}

		if want, got := tt.sc, sc; !reflect.DeepEqual(want, got) {
			t.Fatalf("[%02d] test %q, unexpected value for Options.StatusCode():\n- want: %v\n-  got: %v",
				i, tt.description, want, got)
		}

		if want, got := tt.ok, ok; want != got {
			t.Fatalf("[%02d] test %q, unexpected ok for Options.StatusCode(): %v != %v",
				i, tt.description, want, got)
		}
	}
}

// TestOptionsElapsedTime verifies that Options.ElapsedTime properly parses and
// returns a time.Duration value, if one is available with OptionElapsedTime.
func TestOptionsElapsedTime(t *testing.T) {
	var tests = []struct {
		description string
		options     Options
		duration    time.Duration
		ok          bool
		err         error
	}{
		{
			description: "OptionElapsedTime not present in Options map",
		},
		{
			description: "OptionElapsedTime present in Options map, but too short",
			options: Options{
				OptionElapsedTime: [][]byte{{1}},
			},
			err: errInvalidElapsedTime,
		},
		{
			description: "OptionElapsedTime present in Options map, but too long",
			options: Options{
				OptionElapsedTime: [][]byte{{1, 2, 3}},
			},
			err: errInvalidElapsedTime,
		},
		{
			description: "OptionElapsedTime present in Options map",
			options: Options{
				OptionElapsedTime: [][]byte{{1, 1}},
			},
			duration: 2570 * time.Millisecond,
			ok:       true,
		},
	}

	for i, tt := range tests {
		duration, ok, err := tt.options.ElapsedTime()
		if err != nil {
			if want, got := tt.err, err; want != got {
				t.Fatalf("[%02d] test %q, unexpected error for Options.ElapsedTime: %v != %v",
					i, tt.description, want, got)
			}

			continue
		}

		if want, got := tt.duration, duration; want != got {
			t.Fatalf("[%02d] test %q, unexpected value for Options.ElapsedTime(): %v != %v",
				i, tt.description, want, got)
		}

		if want, got := tt.ok, ok; want != got {
			t.Fatalf("[%02d] test %q, unexpected ok for Options.ElapsedTime(): %v != %v",
				i, tt.description, want, got)
		}
	}
}

// TestOptionsRapidCommit verifies that Options.RapidCommit properly indicates
// if OptionRapidCommit was present in Options.
func TestOptionsRapidCommit(t *testing.T) {
	var tests = []struct {
		description string
		options     Options
		ok          bool
		err         error
	}{
		{
			description: "OptionRapidCommit not present in Options map",
		},
		{
			description: "OptionRapidCommit present in Options map, but non-empty",
			options: Options{
				OptionRapidCommit: [][]byte{{1}},
			},
			err: errInvalidRapidCommit,
		},
		{
			description: "OptionRapidCommit present in Options map, empty",
			options: Options{
				OptionRapidCommit: [][]byte{},
			},
			ok: true,
		},
	}

	for i, tt := range tests {
		ok, err := tt.options.RapidCommit()
		if err != nil {
			if want, got := tt.err, err; want != got {
				t.Fatalf("[%02d] test %q, unexpected error for Options.RapidCommit: %v != %v",
					i, tt.description, want, got)
			}

			continue
		}

		if want, got := tt.ok, ok; want != got {
			t.Fatalf("[%02d] test %q, unexpected ok for Options.RapidCommit(): %v != %v",
				i, tt.description, want, got)
		}
	}
}

// TestOptionsUserClass verifies that Options.UserClass properly parses
// and returns raw user class data, if it is available with OptionUserClass.
func TestOptionsUserClass(t *testing.T) {
	var tests = []struct {
		description string
		options     Options
		classes     [][]byte
		ok          bool
		err         error
	}{
		{
			description: "OptionUserClass not present in Options map",
		},
		{
			description: "OptionUserClass present in Options map, but empty",
			options: Options{
				OptionUserClass: [][]byte{{}},
			},
			err: errInvalidClass,
		},
		{
			description: "OptionUserClass present in Options map, one item, zero length",
			options: Options{
				OptionUserClass: [][]byte{{
					0, 0,
				}},
			},
			classes: [][]byte{{}},
			ok:      true,
		},
		{
			description: "OptionUserClass present in Options map, one item, extra byte",
			options: Options{
				OptionUserClass: [][]byte{{
					0, 1, 1, 255,
				}},
			},
			err: errInvalidClass,
		},
		{
			description: "OptionUserClass present in Options map, one item",
			options: Options{
				OptionUserClass: [][]byte{{
					0, 1, 1,
				}},
			},
			classes: [][]byte{{1}},
			ok:      true,
		},
		{
			description: "OptionUserClass present in Options map, three items",
			options: Options{
				OptionUserClass: [][]byte{{
					0, 1, 1,
					0, 2, 2, 2,
					0, 3, 3, 3, 3,
				}},
			},
			classes: [][]byte{{1}, {2, 2}, {3, 3, 3}},
			ok:      true,
		},
	}

	for i, tt := range tests {
		classes, ok, err := tt.options.UserClass()
		if err != nil {
			if want, got := tt.err, err; want != got {
				t.Fatalf("[%02d] test %q, unexpected error for Options.UserClass: %v != %v",
					i, tt.description, want, got)
			}

			continue
		}

		if want, got := len(tt.classes), len(classes); want != got {
			t.Fatalf("[%02d] test %q, unexpected classes slice length: %v != %v",
				i, tt.description, want, got)

		}

		for j := range classes {
			if want, got := tt.classes[j], classes[j]; !bytes.Equal(want, got) {
				t.Fatalf("[%02d:%02d] test %q, unexpected value for Options.UserClass()\n- want: %v\n-  got: %v",
					i, j, tt.description, want, got)
			}
		}

		if want, got := tt.ok, ok; want != got {
			t.Fatalf("[%02d] test %q, unexpected ok for Options.UserClass(): %v != %v",
				i, tt.description, want, got)
		}
	}
}

// TestOptionsVendorClass verifies that Options.VendorClass properly parses
// and returns raw vendor class data, if it is available with OptionVendorClass.
func TestOptionsVendorClass(t *testing.T) {
	var tests = []struct {
		description string
		options     Options
		classes     [][]byte
		ok          bool
		err         error
	}{
		{
			description: "OptionVendorClass not present in Options map",
		},
		{
			description: "OptionVendorClass present in Options map, but empty",
			options: Options{
				OptionVendorClass: [][]byte{{}},
			},
			err: errInvalidClass,
		},
		{
			description: "OptionVendorClass present in Options map, one item, zero length",
			options: Options{
				OptionVendorClass: [][]byte{{
					0, 0,
				}},
			},
			classes: [][]byte{{}},
			ok:      true,
		},
		{
			description: "OptionVendorClass present in Options map, one item, extra byte",
			options: Options{
				OptionVendorClass: [][]byte{{
					0, 1, 1, 255,
				}},
			},
			err: errInvalidClass,
		},
		{
			description: "OptionVendorClass present in Options map, one item",
			options: Options{
				OptionVendorClass: [][]byte{{
					0, 1, 1,
				}},
			},
			classes: [][]byte{{1}},
			ok:      true,
		},
		{
			description: "OptionVendorClass present in Options map, three items",
			options: Options{
				OptionVendorClass: [][]byte{{
					0, 1, 1,
					0, 2, 2, 2,
					0, 3, 3, 3, 3,
				}},
			},
			classes: [][]byte{{1}, {2, 2}, {3, 3, 3}},
			ok:      true,
		},
	}

	for i, tt := range tests {
		classes, ok, err := tt.options.VendorClass()
		if err != nil {
			if want, got := tt.err, err; want != got {
				t.Fatalf("[%02d] test %q, unexpected error for Options.VendorClass: %v != %v",
					i, tt.description, want, got)
			}

			continue
		}

		if want, got := len(tt.classes), len(classes); want != got {
			t.Fatalf("[%02d] test %q, unexpected classes slice length: %v != %v",
				i, tt.description, want, got)

		}

		for j := range classes {
			if want, got := tt.classes[j], classes[j]; !bytes.Equal(want, got) {
				t.Fatalf("[%02d:%02d] test %q, unexpected value for Options.VendorClass()\n- want: %v\n-  got: %v",
					i, j, tt.description, want, got)
			}
		}

		if want, got := tt.ok, ok; want != got {
			t.Fatalf("[%02d] test %q, unexpected ok for Options.VendorClass(): %v != %v",
				i, tt.description, want, got)
		}
	}
}

// TestOptions_enumerate verifies that Options.enumerate correctly enumerates
// and sorts an Options map into key/value option pairs.
func TestOptions_enumerate(t *testing.T) {
	var tests = []struct {
		description string
		options     Options
		kv          optslice
	}{
		{
			description: "one key/value pair",
			options: Options{
				1: [][]byte{[]byte("foo")},
			},
			kv: optslice{
				option{
					Code: 1,
					Data: []byte("foo"),
				},
			},
		},
		{
			description: "two key/value pairs",
			options: Options{
				1: [][]byte{[]byte("foo")},
				2: [][]byte{[]byte("bar")},
			},
			kv: optslice{
				option{
					Code: 1,
					Data: []byte("foo"),
				},
				option{
					Code: 2,
					Data: []byte("bar"),
				},
			},
		},
		{
			description: "four key/value pairs, two with same key",
			options: Options{
				1: [][]byte{[]byte("foo"), []byte("baz")},
				3: [][]byte{[]byte("qux")},
				2: [][]byte{[]byte("bar")},
			},
			kv: optslice{
				option{
					Code: 1,
					Data: []byte("foo"),
				},
				option{
					Code: 1,
					Data: []byte("baz"),
				},
				option{
					Code: 2,
					Data: []byte("bar"),
				},
				option{
					Code: 3,
					Data: []byte("qux"),
				},
			},
		},
	}

	for i, tt := range tests {
		if want, got := tt.kv, tt.options.enumerate(); !reflect.DeepEqual(want, got) {
			t.Fatalf("[%02d] test %q, unexpected key/value options:\n- want: %v\n-  got: %v",
				i, tt.description, want, got)
		}
	}
}

// Test_parseOptions verifies that parseOptions parses correct option values
// from a slice of bytes, and that it returns an empty Options map if the byte
// slice cannot contain options.
func Test_parseOptions(t *testing.T) {
	var tests = []struct {
		description string
		buf         []byte
		options     Options
	}{
		{
			description: "nil options bytes",
			buf:         nil,
			options:     Options{},
		},
		{
			description: "empty options bytes",
			buf:         []byte{},
			options:     Options{},
		},
		{
			description: "too short options bytes",
			buf:         []byte{0},
			options:     Options{},
		},
		{
			description: "zero code, zero length option bytes",
			buf:         []byte{0, 0, 0, 0},
			options:     Options{},
		},
		{
			description: "zero code, zero length option bytes with trailing byte",
			buf:         []byte{0, 0, 0, 0, 1},
			options:     Options{},
		},
		{
			description: "zero code, length 3, incorrect length for data",
			buf:         []byte{0, 0, 0, 3, 1, 2},
			options:     Options{},
		},
		{
			description: "client ID, length 1, value [1]",
			buf:         []byte{0, 1, 0, 1, 1},
			options: Options{
				OptionClientID: [][]byte{{1}},
			},
		},
		{
			description: "client ID, length 2, value [1 1] + server ID, length 3, value [1 2 3]",
			buf: []byte{
				0, 1, 0, 2, 1, 1,
				0, 2, 0, 3, 1, 2, 3,
			},
			options: Options{
				OptionClientID: [][]byte{{1, 1}},
				OptionServerID: [][]byte{{1, 2, 3}},
			},
		},
	}

	for i, tt := range tests {
		if want, got := tt.options, parseOptions(tt.buf); !reflect.DeepEqual(want, got) {
			t.Fatalf("[%02d] test %q, unexpected Options map for parseOptions(%v):\n- want: %v\n-  got: %v",
				i, tt.description, tt.buf, want, got)
		}
	}
}
