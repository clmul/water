//go:build darwin || linux
// +build darwin linux

package water

import (
	"golang.org/x/sys/unix"
	"log"
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
	fd   int
	name string
}

// Name returns the interface name of ifce, e.g. tun0, tap1, tun0, etc..
func (ifce *Interface) Name() string {
	return ifce.name
}

func (ifce *Interface) Fd() int {
	return ifce.fd
}

func file(fd uintptr, name string) *os.File {
	err := unix.SetNonblock(int(fd), true)
	if err != nil {
		log.Println(err)
	}
	return os.NewFile(fd, name)
}

func New(c Config) (*Interface, error) {
	fd, name, err := open(c)
	if err != nil {
		return nil, err
	}
	ifce := &Interface{
		File: file(uintptr(fd), name),
		name: name,
	}
	return ifce, nil
}
