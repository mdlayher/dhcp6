package dhcp6

import (
	"encoding/binary"
)

var order = binary.BigEndian

// buffer encapsulates marshaling unsigned integer and byte slice values.
type buffer struct {
	// data is the underlying data.
	data []byte
}

func newBuffer(b []byte) *buffer {
	return &buffer{b}
}

// append appends n bytes to the buffer and returns a slice pointing to the
// newly appended bytes.
func (b *buffer) append(n int) []byte {
	b.data = append(b.data, make([]byte, n)...)
	return b.data[len(b.data)-n:]
}

// Data is unconsumed data remaining in the buffer.
func (b *buffer) Data() []byte {
	return b.data
}

// Remaining consumes and returns a copy of all remaining bytes in the buffer.
func (b *buffer) Remaining() []byte {
	p := b.Consume(len(b.Data()))
	cp := make([]byte, len(p))
	copy(cp, p)
	return cp
}

// consume consumes n bytes from the buffer. It returns nil, false if there
// aren't enough bytes left.
func (b *buffer) consume(n int) ([]byte, bool) {
	if !b.Has(n) {
		return nil, false
	}
	rval := b.data[:n]
	b.data = b.data[n:]
	return rval, true
}

// Consume consumes n bytes from the buffer. It returns nil if there aren't
// enough bytes left.
func (b *buffer) Consume(n int) []byte {
	v, ok := b.consume(n)
	if !ok {
		return nil
	}
	return v
}

// Has returns true if n bytes are available.
func (b *buffer) Has(n int) bool {
	return len(b.data) >= n
}

// Len returns the length of the remaining bytes.
func (b *buffer) Len() int {
	return len(b.data)
}

// Read8 reads a byte from the buffer.
func (b *buffer) Read8() uint8 {
	v, ok := b.consume(1)
	if !ok {
		return 0
	}
	return uint8(v[0])
}

// Read16 reads a 16-bit value from the buffer.
func (b *buffer) Read16() uint16 {
	v, ok := b.consume(2)
	if !ok {
		return 0
	}
	return order.Uint16(v)
}

// Read32 reads a 32-bit value from the buffer.
func (b *buffer) Read32() uint32 {
	v, ok := b.consume(4)
	if !ok {
		return 0
	}
	return order.Uint32(v)
}

// Read64 reads a 64-bit value from the buffer.
func (b *buffer) Read64() uint64 {
	v, ok := b.consume(8)
	if !ok {
		return 0
	}
	return order.Uint64(v)
}

// ReadBytes reads exactly len(p) values from the buffer.
func (b *buffer) ReadBytes(p []byte) {
	copy(p, b.Consume(len(p)))
}

// Write8 writes a byte to the buffer.
func (b *buffer) Write8(v uint8) {
	b.append(1)[0] = byte(v)
}

// Write16 writes a 16-bit value to the buffer.
func (b *buffer) Write16(v uint16) {
	order.PutUint16(b.append(2), v)
}

// Write32 writes a 32-bit value to the buffer.
func (b *buffer) Write32(v uint32) {
	order.PutUint32(b.append(4), v)
}

// Write64 writes a 64-bit value to the buffer.
func (b *buffer) Write64(v uint64) {
	order.PutUint64(b.append(8), v)
}

// WriteN returns a newly appended n-size buffer to write to.
func (b *buffer) WriteN(n int) []byte {
	return b.append(n)
}

// WriteBytes writes p to the buffer.
func (b *buffer) WriteBytes(p []byte) {
	copy(b.append(len(p)), p)
}
