package water

import (
	"unsafe"

	"golang.org/x/sys/unix"
)

type Config struct{}

const appleUTUNCtl = "com.apple.net.utun_control"

/*
 * From ioctl.h:
 * #define	IOCPARM_MASK	0x1fff		// parameter length, at most 13 bits
 * ...
 * #define	IOC_OUT		0x40000000	// copy out parameters
 * #define	IOC_IN		0x80000000	// copy in parameters
 * #define	IOC_INOUT	(IOC_IN|IOC_OUT)
 * ...
 * #define _IOC(inout,group,num,len) \
 * 	(inout | ((len & IOCPARM_MASK) << 16) | ((group) << 8) | (num))
 * ...
 * #define	_IOWR(g,n,t)	_IOC(IOC_INOUT,	(g), (n), sizeof(t))
 *
 * From kern_control.h:
 * #define CTLIOCGINFO     _IOWR('N', 3, struct ctl_info)	// get id from name
 *
 */

const appleCTLIOCGINFO = (0x40000000 | 0x80000000) | ((100 & 0x1fff) << 16) | uint32(byte('N'))<<8 | 3

/*
 * #define _IOW(g,n,t) _IOC(IOC_IN, (g), (n), sizeof(t))
 * #define TUNSIFMODE _IOW('t', 94, int)
 */
const appleTUNSIFMODE = (0x80000000) | ((4 & 0x1fff) << 16) | uint32(byte('t'))<<8 | 94

/*
 * struct sockaddr_ctl {
 *     u_char sc_len; // depends on size of bundle ID string
 *     u_char sc_family; // AF_SYSTEM
 *     u_int16_t ss_sysaddr; // AF_SYS_KERNCONTROL
 *     u_int32_t sc_id; // Controller unique identifier
 *     u_int32_t sc_unit; // Developer private unit number
 *     u_int32_t sc_reserved[5];
 * };
 */
type sockaddrCtl struct {
	scLen      uint8
	scFamily   uint8
	ssSysaddr  uint16
	scID       uint32
	scUnit     uint32
	scReserved [5]uint32
}

var sockaddrCtlSize uintptr = 32

func open(Config) (int, string, error) {
	// Supposed to be socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL), but ...
	//
	// In sys/socket.h:
	// #define PF_SYSTEM	AF_SYSTEM
	//
	// In sys/sys_domain.h:
	// #define SYSPROTO_CONTROL       	2	/* kernel control protocol */
	fd, err := unix.Socket(unix.AF_SYSTEM, unix.SOCK_DGRAM, 2)
	if err != nil {
		return 0, "", err
	}

	var ctlInfo = &struct {
		ctlID   uint32
		ctlName [96]byte
	}{}
	copy(ctlInfo.ctlName[:], []byte(appleUTUNCtl))

	_, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), uintptr(appleCTLIOCGINFO), uintptr(unsafe.Pointer(ctlInfo)))
	if errno != 0 {
		return 0, "", errno
	}

	addrP := unsafe.Pointer(&sockaddrCtl{
		scLen:    uint8(sockaddrCtlSize),
		scFamily: unix.AF_SYSTEM,

		/* #define AF_SYS_CONTROL 2 */
		ssSysaddr: 2,

		scID:   ctlInfo.ctlID,
		scUnit: 0,
	})
	_, _, errno = unix.Syscall(unix.SYS_CONNECT, uintptr(fd), uintptr(addrP), uintptr(sockaddrCtlSize))
	if errno != 0 {
		return 0, "", errno
	}

	var ifName [16]byte
	ifNameSize := uintptr(16)
	_, _, errno = unix.Syscall6(unix.SYS_GETSOCKOPT, uintptr(fd),
		2, /* #define SYSPROTO_CONTROL 2 */
		2, /* #define UTUN_OPT_IFNAME 2 */
		uintptr(unsafe.Pointer(&ifName)),
		uintptr(unsafe.Pointer(&ifNameSize)), 0)
	if errno != 0 {
		return 0, "", errno
	}

	name := string(ifName[:ifNameSize-1])
	return fd, name, nil
}

// this is a hack to work around the first 4 bytes "packet information"
// because there doesn't seem to be an IFF_NO_PI for darwin.
func (ifce *Interface) Read(buffer []byte) (int, error) {
	n, err := ifce.File.Read(buffer)
	if err != nil {
		return 0, err
	}
	copy(buffer, buffer[4:])
	return n - 4, nil
}

func (ifce *Interface) Write(buffer []byte) (int, error) {
	// Determine the IP Family for the NULL L2 Header
	buffer = buffer[:len(buffer)+4]
	copy(buffer[4:], buffer)
	ipVer := buffer[0] >> 4
	switch ipVer {
	case 4:
		buffer[3] = unix.AF_INET
	case 6:
		buffer[3] = unix.AF_INET6
	default:
		panic("unable to determine IP version from packet")
	}

	buffer[0] = 0
	buffer[1] = 0
	buffer[2] = 0

	n, err := ifce.File.Write(buffer)
	return n - 4, err
}
