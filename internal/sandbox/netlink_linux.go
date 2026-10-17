//go:build linux

package sandbox

import (
	"encoding/binary"
	"syscall"
	"unsafe"
)

// loUp brings the loopback interface up in the new network namespace.
func loUp() error {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, 0)
	if err != nil {
		return err
	}
	defer syscall.Close(fd)
	var ifr [40]byte
	copy(ifr[:], "lo")
	if _, _, e := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), syscall.SIOCGIFFLAGS, uintptr(unsafe.Pointer(&ifr[0]))); e != 0 {
		return e
	}
	flags := binary.LittleEndian.Uint16(ifr[16:]) | syscall.IFF_UP
	binary.LittleEndian.PutUint16(ifr[16:], flags)
	if _, _, e := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), syscall.SIOCSIFFLAGS, uintptr(unsafe.Pointer(&ifr[0]))); e != 0 {
		return e
	}
	return nil
}

// routeAllLocal adds "local 0.0.0.0/0 dev lo": every IPv4 address becomes
// local, so a connection to any IP reaches the sandbox listeners and its
// destination can be recorded.
func routeAllLocal() error {
	fd, err := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_RAW, syscall.NETLINK_ROUTE)
	if err != nil {
		return err
	}
	defer syscall.Close(fd)
	if err := syscall.Bind(fd, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}); err != nil {
		return err
	}
	ifindex := uint32(1)
	if ifi, err := interfaceIndex("lo"); err == nil {
		ifindex = ifi
	}
	attr := func(typ uint16, val []byte) []byte {
		b := make([]byte, 4+len(val))
		binary.LittleEndian.PutUint16(b[0:], uint16(4+len(val)))
		binary.LittleEndian.PutUint16(b[2:], typ)
		copy(b[4:], val)
		for len(b)%4 != 0 {
			b = append(b, 0)
		}
		return b
	}
	u32 := func(v uint32) []byte { b := make([]byte, 4); binary.LittleEndian.PutUint32(b, v); return b }
	rt := []byte{syscall.AF_INET, 0, 0, 0, syscall.RT_TABLE_LOCAL, syscall.RTPROT_BOOT, syscall.RT_SCOPE_HOST, syscall.RTN_LOCAL, 0, 0, 0, 0}
	body := append(rt, attr(syscall.RTA_OIF, u32(ifindex))...)
	msg := make([]byte, 16, 16+len(body))
	binary.LittleEndian.PutUint32(msg[0:], uint32(16+len(body)))
	binary.LittleEndian.PutUint16(msg[4:], syscall.RTM_NEWROUTE)
	binary.LittleEndian.PutUint16(msg[6:], syscall.NLM_F_REQUEST|syscall.NLM_F_CREATE|syscall.NLM_F_EXCL|syscall.NLM_F_ACK)
	binary.LittleEndian.PutUint32(msg[8:], 1)
	msg = append(msg, body...)
	if err := syscall.Sendto(fd, msg, 0, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}); err != nil {
		return err
	}
	buf := make([]byte, 4096)
	n, _, err := syscall.Recvfrom(fd, buf, 0)
	if err != nil {
		return err
	}
	msgs, err := syscall.ParseNetlinkMessage(buf[:n])
	if err != nil {
		return err
	}
	for _, m := range msgs {
		if m.Header.Type == syscall.NLMSG_ERROR && len(m.Data) >= 4 {
			if code := int32(binary.LittleEndian.Uint32(m.Data)); code != 0 {
				return syscall.Errno(-code)
			}
		}
	}
	return nil
}

func interfaceIndex(name string) (uint32, error) {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, 0)
	if err != nil {
		return 0, err
	}
	defer syscall.Close(fd)
	var ifr [40]byte
	copy(ifr[:], name)
	if _, _, e := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), syscall.SIOCGIFINDEX, uintptr(unsafe.Pointer(&ifr[0]))); e != 0 {
		return 0, e
	}
	return binary.LittleEndian.Uint32(ifr[16:]), nil
}
