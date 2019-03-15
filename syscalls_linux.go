package water

import (
	"errors"
	"os"
	"strings"
	"syscall"
	"unsafe"

	"golang.zx2c4.com/wireguard/tun"

	"golang.org/x/sys/unix"
)

const (
	cIFFTUN        = 0x0001
	cIFFTAP        = 0x0002
	cIFFNOPI       = 0x1000
	cIFFMULTIQUEUE = 0x0100
)

type ifReq struct {
	Name  [0x10]byte
	Flags uint16
	pad   [0x28 - 0x10 - 2]byte
}

func ioctl(fd uintptr, request uintptr, argp uintptr) error {
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, fd, uintptr(request), argp)
	if errno != 0 {
		return os.NewSyscallError("ioctl", errno)
	}
	return nil
}

func newTAP(config Config) (ifce *Interface, err error) {
	fdInt, err := syscall.Open("/dev/net/tun", os.O_RDWR|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	fd := uintptr(fdInt)

	var flags uint16
	flags = cIFFTAP | cIFFNOPI
	if config.PlatformSpecificParams.MultiQueue {
		flags |= cIFFMULTIQUEUE
	}
	name, err := createInterface(fd, config.Name, flags)
	if err != nil {
		return nil, err
	}

	if err = setDeviceOptions(fd, config); err != nil {
		return nil, err
	}
	f := os.NewFile(fd, "tun")

	err = setMTU(config.MTU, name)
	if err != nil {
		f.Close()
		return nil, err
	}

	events := make(chan tun.TUNEvent, 5)
	go func() {
		for {
			select {
			case ev := <-events:
				if ev == 0 {
					break
				} else if ev == tun.TUNEventMTUUpdate {
					setMTU(config.MTU, name)
				} else {
					// not implemented
				}
			}
		}
	}()

	ifce = &Interface{isTAP: true, file: f, name: name, events: events}
	return
}

func newTUN(config Config) (ifce *Interface, err error) {
	fdInt, err := syscall.Open("/dev/net/tun", os.O_RDWR|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	fd := uintptr(fdInt)

	var flags uint16
	flags = cIFFTUN | cIFFNOPI
	if config.PlatformSpecificParams.MultiQueue {
		flags |= cIFFMULTIQUEUE
	}
	name, err := createInterface(fd, config.Name, flags)
	if err != nil {
		return nil, err
	}

	if err = setDeviceOptions(fd, config); err != nil {
		return nil, err
	}
	f := os.NewFile(fd, "tun")

	err = setMTU(config.MTU, name)
	if err != nil {
		f.Close()
		return nil, err
	}

	events := make(chan tun.TUNEvent, 5)
	go func() {
		for {
			select {
			case ev := <-events:
				if ev == 0 {
					break
				} else if ev == tun.TUNEventMTUUpdate {
					setMTU(config.MTU, name)
				} else {
					// not implemented
				}
			}
		}
	}()

	ifce = &Interface{isTAP: false, file: f, name: name, events: events}
	return
}

func createInterface(fd uintptr, ifName string, flags uint16) (createdIFName string, err error) {
	var req ifReq
	req.Flags = flags
	copy(req.Name[:], ifName)

	err = ioctl(fd, syscall.TUNSETIFF, uintptr(unsafe.Pointer(&req)))
	if err != nil {
		return
	}

	createdIFName = strings.Trim(string(req.Name[:]), "\x00")
	return
}

func setDeviceOptions(fd uintptr, config Config) (err error) {
	if config.Permissions != nil {
		if err = ioctl(fd, syscall.TUNSETOWNER, uintptr(config.Permissions.Owner)); err != nil {
			return
		}
		if err = ioctl(fd, syscall.TUNSETGROUP, uintptr(config.Permissions.Group)); err != nil {
			return
		}
	}

	// set clear the persist flag
	value := 0
	if config.Persist {
		value = 1
	}
	return ioctl(fd, syscall.TUNSETPERSIST, uintptr(value))
}

func mtu(name string) (int, error) {
	fd, err := unix.Socket(
		unix.AF_INET,
		unix.SOCK_DGRAM,
		0,
	)
	if err != nil {
		return 0, err
	}
	defer unix.Close(fd)

	var ifr [unix.IFNAMSIZ + 64]byte
	copy(ifr[:], name)
	_, _, errno := unix.Syscall(
		unix.SYS_IOCTL,
		uintptr(fd),
		uintptr(unix.SIOCGIFMTU),
		uintptr(unsafe.Pointer(&ifr[0])),
	)
	if errno != 0 {
		return 0, errors.New("failed to get MTU of TUN device: " + errno.Error())
	}

	return int(*(*int32)(unsafe.Pointer(&ifr[unix.IFNAMSIZ]))), nil
}

func setMTU(n int, name string) error {
	fd, err := unix.Socket(
		unix.AF_INET,
		unix.SOCK_DGRAM,
		0,
	)
	if err != nil {
		return err
	}
	defer unix.Close(fd)

	var ifr [unix.IFNAMSIZ + 64]byte
	copy(ifr[:], name)
	*(*uint32)(unsafe.Pointer(&ifr[unix.IFNAMSIZ])) = uint32(n)
	_, _, errno := unix.Syscall(
		unix.SYS_IOCTL,
		uintptr(fd),
		uintptr(unix.SIOCSIFMTU),
		uintptr(unsafe.Pointer(&ifr[0])),
	)
	if errno != 0 {
		return errors.New("failed to set MTU of TUN device")
	}

	return nil
}
