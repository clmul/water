// +build darwin linux

package water

import (
	"os"
	_ "unsafe"
)

// Interface is a TUN/TAP interface.
//
// MultiQueue(Linux kernel > 3.8): With MultiQueue enabled, user should hold multiple
// interfaces to send/receive packet in parallel.
// Kernel document about MultiQueue: https://www.kernel.org/doc/Documentation/networking/tuntap.txt
type Interface struct {
	*os.File
	name string
}

// Name returns the interface name of ifce, e.g. tun0, tap1, tun0, etc..
func (ifce *Interface) Name() string {
	return ifce.name
}

//go:linkname newFile os.newFile
func newFile(fd uintptr, name string, kind int) *os.File

func file(fd uintptr, name string) *os.File {
	return newFile(fd, name, 1)
}
