package main

import (
	"encoding/binary"
	"net"
	"syscall"
	"unsafe"
)

const soOriginalDst = 80

func getOriginalDst(conn *net.TCPConn) (*net.TCPAddr, error) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return nil, err
	}

	var (
		addr    *net.TCPAddr
		sockErr error
	)
	if ctrlErr := raw.Control(func(fd uintptr) {
		addr, sockErr = originalDstOfFD(int(fd))
	}); ctrlErr != nil {
		return nil, ctrlErr
	}
	if sockErr != nil {
		return nil, sockErr
	}
	return addr, nil
}

func originalDstOfFD(fd int) (*net.TCPAddr, error) {
	addr4 := &syscall.RawSockaddrInet4{}
	optLen := uint32(syscall.SizeofSockaddrInet4)
	_, _, errno := syscall.Syscall6(
		syscall.SYS_GETSOCKOPT,
		uintptr(fd),
		uintptr(syscall.SOL_IP),
		uintptr(soOriginalDst),
		uintptr(unsafe.Pointer(addr4)),
		uintptr(unsafe.Pointer(&optLen)),
		0,
	)
	if errno == 0 && optLen >= uint32(syscall.SizeofSockaddrInet4) {
		return &net.TCPAddr{
			IP:   net.IP(addr4.Addr[:]),
			Port: ntohs(addr4.Port),
		}, nil
	}

	addr6 := &syscall.RawSockaddrInet6{}
	optLen = uint32(syscall.SizeofSockaddrInet6)
	_, _, errno = syscall.Syscall6(
		syscall.SYS_GETSOCKOPT,
		uintptr(fd),
		uintptr(syscall.SOL_IPV6),
		uintptr(soOriginalDst),
		uintptr(unsafe.Pointer(addr6)),
		uintptr(unsafe.Pointer(&optLen)),
		0,
	)
	if errno == 0 && optLen >= uint32(syscall.SizeofSockaddrInet6) {
		return &net.TCPAddr{
			IP:   net.IP(addr6.Addr[:]),
			Port: ntohs(addr6.Port),
		}, nil
	}

	if errno == 0 {
		errno = syscall.EINVAL
	}
	return nil, errno
}

func ntohs(p uint16) int {
	return int(binary.BigEndian.Uint16((*[2]byte)(unsafe.Pointer(&p))[:]))
}
