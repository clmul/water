package water

import (
	"strings"
	"unsafe"

	"golang.org/x/sys/unix"
)

const (
	cIFF_TUN         = 0x0001
	cIFF_TAP         = 0x0002
	cIFF_NO_PI       = 0x1000
	cIFF_MULTI_QUEUE = 0x0100
)

type ifReq struct {
	Name  [0x10]byte
	Flags uint16
	pad   [0x28 - 0x10 - 2]byte
}

func ioctl(fd int, request uintptr, argp uintptr) error {
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), request, argp)
	if errno != 0 {
		return errno
	}
	return nil
}

const (
	devfile = "/dev/net/tun"
)

func createDevNetTun() error {
	err := unix.Mkdir("/dev/net", 0755)
	if err != nil {
		return err
	}
	dev := unix.Mkdev(10, 200)
	err = unix.Mknod(devfile, unix.S_IFCHR|0666, int(dev))
	return err
}

func openDevNetTun() (int, error){
	fd, err := unix.Open(devfile, unix.O_RDWR, 0)
	if err == nil {
		return fd, nil
	}
	if err != unix.ENOENT {
		return 0, err
	}
	err = createDevNetTun()
	if err != nil {
		return 0, err
	}
	return unix.Open(devfile, unix.O_RDWR, 0)
}

func New(config Config) (ifce *Interface, err error) {
	fd, err := openDevNetTun()
	if err != nil {
		return nil, err
	}

	var flags uint16
	flags = cIFF_TUN | cIFF_NO_PI
	if config.MultiQueue {
		flags |= cIFF_MULTI_QUEUE
	}
	name, err := createInterface(fd, config.Name, flags)
	if err != nil {
		return nil, err
	}

	if err = setDeviceOptions(fd, config); err != nil {
		return nil, err
	}

	ifce = &Interface{
		File: file(uintptr(fd), name),
		name: name,
	}
	return
}

func createInterface(fd int, ifName string, flags uint16) (createdIFName string, err error) {
	var req ifReq
	req.Flags = flags
	copy(req.Name[:], ifName)

	err = ioctl(fd, unix.TUNSETIFF, uintptr(unsafe.Pointer(&req)))
	if err != nil {
		return
	}

	createdIFName = strings.Trim(string(req.Name[:]), "\x00")
	return
}

func setDeviceOptions(fd int, config Config) (err error) {
	// Device Permissions
	if config.Permissions != nil {
		// Set Owner
		if err = ioctl(fd, unix.TUNSETOWNER, uintptr(config.Permissions.Owner)); err != nil {
			return
		}

		// Set Group
		if err = ioctl(fd, unix.TUNSETGROUP, uintptr(config.Permissions.Group)); err != nil {
			return
		}
	}

	// Set/Clear Persist Device Flag
	value := 0
	if config.Persist {
		value = 1
	}
	return ioctl(fd, unix.TUNSETPERSIST, uintptr(value))
}
