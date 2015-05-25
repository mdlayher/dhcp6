package dhcp6

import (
	"bytes"
	"reflect"
	"testing"
	"time"
)

// TestOptionsAdd verifies that Options.Add correctly creates or appends
// key/value Option pairs to an Options map.
func TestOptionsAdd(t *testing.T) {
	var tests = []struct {
		description string
		kv          []option
		options     Options
	}{
		{
			description: "one key/value pair",
			kv: []option{
				option{
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
				option{
					Code: 1,
					Data: []byte("foo"),
				},
				option{
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
			o.Add(p.Code, p.Data)
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
				OptionClientID: [][]byte{[]byte{0, 1}},
			},
			duid: DUIDLLT([]byte{0, 1}),
			ok:   true,
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
				OptionServerID: [][]byte{[]byte{0, 1}},
			},
			duid: DUIDLLT([]byte{0, 1}),
			ok:   true,
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
		iana        []IANA
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
				OptionIANA: [][]byte{[]byte{
					1, 2, 3, 4,
					0, 0, 1, 0,
					0, 0, 2, 0,
				}},
			},
			iana: []IANA{
				IANA([]byte{
					1, 2, 3, 4,
					0, 0, 1, 0,
					0, 0, 2, 0,
				}),
			},
			ok: true,
		},
		{
			description: "two OptionIANA present in Options map",
			options: Options{
				OptionIANA: [][]byte{
					bytes.Repeat([]byte{0}, 12),
					bytes.Repeat([]byte{1}, 12),
				},
			},
			iana: []IANA{
				IANA(bytes.Repeat([]byte{0}, 12)),
				IANA(bytes.Repeat([]byte{1}, 12)),
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

		if want, got := tt.iana, iana; !reflect.DeepEqual(want, got) {
			t.Fatalf("[%02d] test %q, unexpected value for Options.IANA():\n- want: %v\n-  got: %v",
				i, tt.description, want, got)
		}

		if want, got := tt.ok, ok; want != got {
			t.Fatalf("[%02d] test %q, unexpected ok for Options.IANA(): %v != %v",
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
		iaaddr      []IAAddr
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
				OptionIAAddr: [][]byte{[]byte{
					0, 0, 0, 0,
					1, 1, 1, 1,
					2, 2, 2, 2,
					3, 3, 3, 3,
					0, 0, 1, 0,
					0, 0, 2, 0,
				}},
			},
			iaaddr: []IAAddr{
				IAAddr([]byte{
					0, 0, 0, 0,
					1, 1, 1, 1,
					2, 2, 2, 2,
					3, 3, 3, 3,
					0, 0, 1, 0,
					0, 0, 2, 0,
				}),
			},
			ok: true,
		},
		{
			description: "two OptionIAAddr present in Options map",
			options: Options{
				OptionIAAddr: [][]byte{
					bytes.Repeat([]byte{0}, 24),
					bytes.Repeat([]byte{1}, 24),
				},
			},
			iaaddr: []IAAddr{
				IAAddr(bytes.Repeat([]byte{0}, 24)),
				IAAddr(bytes.Repeat([]byte{1}, 24)),
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

		if want, got := tt.iaaddr, iaaddr; !reflect.DeepEqual(want, got) {
			t.Fatalf("[%02d] test %q, unexpected value for Options.IAAddr():\n- want: %v\n-  got: %v",
				i, tt.description, want, got)
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
				OptionORO: [][]byte{[]byte{0}},
			},
			err: errInvalidOptionRequest,
		},
		{
			description: "OptionORO present in Options map",
			options: Options{
				OptionORO: [][]byte{[]byte{0, 1}},
			},
			codes: []OptionCode{1},
			ok:    true,
		},
		{
			description: "OptionORO present in Options map, with multiple values",
			options: Options{
				OptionORO: [][]byte{[]byte{0, 1, 0, 2, 0, 3}},
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
		preference  int
		ok          bool
		err         error
	}{
		{
			description: "OptionPreference not present in Options map",
		},
		{
			description: "OptionPreference present in Options map, but too short length",
			options: Options{
				OptionPreference: [][]byte{[]byte{}},
			},
			err: errInvalidPreference,
		},
		{
			description: "OptionPreference present in Options map, but too long length",
			options: Options{
				OptionPreference: [][]byte{[]byte{0, 1}},
			},
			err: errInvalidPreference,
		},
		{
			description: "OptionPreference present in Options map",
			options: Options{
				OptionPreference: [][]byte{[]byte{255}},
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
				OptionElapsedTime: [][]byte{[]byte{1}},
			},
			err: errInvalidElapsedTime,
		},
		{
			description: "OptionElapsedTime present in Options map, but too long",
			options: Options{
				OptionElapsedTime: [][]byte{[]byte{1, 2, 3}},
			},
			err: errInvalidElapsedTime,
		},
		{
			description: "OptionElapsedTime present in Options map",
			options: Options{
				OptionElapsedTime: [][]byte{[]byte{1, 1}},
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

// TestOptions_enumerate verifies that Options.enumerate correctly enumerates
// and sorts an Options map into key/value optain pairs.
func TestOptions_enumerate(t *testing.T) {
	var tests = []struct {
		description string
		options     Options
		kv          []option
	}{
		{
			description: "one key/value pair",
			options: Options{
				1: [][]byte{[]byte("foo")},
			},
			kv: []option{
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
			kv: []option{
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
			kv: []option{
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
// from a slice of bytes, and that it returns a nil option slice if the byte
// slice cannot contain options.
func Test_parseOptions(t *testing.T) {
	var tests = []struct {
		description string
		buf         []byte
		options     []option
	}{
		{
			description: "nil options bytes",
			buf:         nil,
			options:     nil,
		},
		{
			description: "empty options bytes",
			buf:         []byte{},
			options:     nil,
		},
		{
			description: "too short options bytes",
			buf:         []byte{0},
			options:     nil,
		},
		{
			description: "zero code, zero length option bytes",
			buf:         []byte{0, 0, 0, 0},
			options:     nil,
		},
		{
			description: "zero code, zero length option bytes with trailing byte",
			buf:         []byte{0, 0, 0, 0, 1},
			options:     nil,
		},
		{
			description: "zero code, length 3, incorrect length for data",
			buf:         []byte{0, 0, 0, 3, 1, 2},
			options:     nil,
		},
		{
			description: "client ID, length 1, value [1]",
			buf:         []byte{0, 1, 0, 1, 1},
			options: []option{
				option{
					Code: OptionClientID,
					Data: []byte{1},
				},
			},
		},
		{
			description: "client ID, length 2, value [1 1] + server ID, length 3, value [1 2 3]",
			buf: []byte{
				0, 1, 0, 2, 1, 1,
				0, 2, 0, 3, 1, 2, 3,
			},
			options: []option{
				option{
					Code: OptionClientID,
					Data: []byte{1, 1},
				},
				option{
					Code: OptionServerID,
					Data: []byte{1, 2, 3},
				},
			},
		},
	}

	for i, tt := range tests {
		if want, got := tt.options, parseOptions(tt.buf); !reflect.DeepEqual(want, got) {
			t.Fatalf("[%02d] unexpected options slice for parseOptions(%v):\n- want: %v\n-  got: %v",
				i, tt.buf, want, got)
		}
	}
}
