// +build !linux

package dhcp6

import (
	"net"
)

// HardwareType returns ErrNotImplemented, because it is not implemented on
// non-Linux platforms.
func HardwareType(ifi *net.Interface) (uint16, error) {
	return 0, ErrNotImplemented
}
