// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Linux system calls.
// This file is compiled as ordinary Go code,
// but it is also input to mksyscall,
// which parses the //sys lines and generates system call stubs.
// Note that sometimes we use a lowercase //sys name and
// wrap it in our own nicer implementation.

package unix

import (
	"encoding/binary"
	"strconv"
	"syscall"
	"time"
	"unsafe"
)

/*
 * Wrapped
 */

func Access(path string, mode uint32) (err error) {
	return Faccessat(AT_FDCWD, path, mode, 0)
}

func Chmod(path string, mode uint32) (err error) {
	return Fchmodat(AT_FDCWD, path, mode, 0)
}

func Chown(path string, uid int, gid int) (err error) {
	return Fchownat(AT_FDCWD, path, uid, gid, 0)
}

func Creat(path string, mode uint32) (fd int, err error) {
	return Open(path, O_CREAT|O_WRONLY|O_TRUNC, mode)
}

func EpollCreate(size int) (fd int, err error) {
	if size <= 0 {
		return -1, EINVAL
	}
	return EpollCreate1(0)
}

//sys	FanotifyInit(flags uint, event_f_flags uint) (fd int, err error)
//sys	fanotifyMark(fd int, flags uint, mask uint64, dirFd int, pathname *byte) (err error)

func FanotifyMark(fd int, flags uint, mask uint64, dirFd int, pathname string) (err error) {
	if pathname == "" {
		return fanotifyMark(fd, flags, mask, dirFd, nil)
	}
	p, err := BytePtrFromString(pathname)
	if err != nil {
		return err
	}
	return fanotifyMark(fd, flags, mask, dirFd, p)
}

//sys	fchmodat(dirfd int, path string, mode uint32) (err error)
//sys	fchmodat2(dirfd int, path string, mode uint32, flags int) (err error)

func Fchmodat(dirfd int, path string, mode uint32, flags int) error {
	// Linux fchmodat doesn't support the flags parameter, but fchmodat2 does.
	// Try fchmodat2 if flags are specified.
	if flags != 0 {
		err := fchmodat2(dirfd, path, mode, flags)
		if err == ENOSYS {
			// fchmodat2 isn't available. If the flags are known to be valid,
			// return EOPNOTSUPP to indicate that fchmodat doesn't support them.
			if flags&^(AT_SYMLINK_NOFOLLOW|AT_EMPTY_PATH) != 0 {
				return EINVAL
			} else if flags&(AT_SYMLINK_NOFOLLOW|AT_EMPTY_PATH) != 0 {
				return EOPNOTSUPP
			}
		}
		return err
	}
	return fchmodat(dirfd, path, mode)
}

func InotifyInit() (fd int, err error) {
	return InotifyInit1(0)
}

//sys	ioctl(fd int, req uint, arg uintptr) (err error) = SYS_IOCTL
//sys	ioctlPtr(fd int, req uint, arg unsafe.Pointer) (err error) = SYS_IOCTL

// ioctl itself should not be exposed directly, but additional get/set functions
// for specific types are permissible. These are defined in ioctl.go and
// ioctl_linux.go.
//
// The third argument to ioctl is often a pointer but sometimes an integer.
// Callers should use ioctlPtr when the third argument is a pointer and ioctl
// when the third argument is an integer.
//
// TODO: some existing code incorrectly uses ioctl when it should use ioctlPtr.

//sys	Linkat(olddirfd int, oldpath string, newdirfd int, newpath string, flags int) (err error)

func Link(oldpath string, newpath string) (err error) {
	return Linkat(AT_FDCWD, oldpath, AT_FDCWD, newpath, 0)
}

func Mkdir(path string, mode uint32) (err error) {
	return Mkdirat(AT_FDCWD, path, mode)
}

func Mknod(path string, mode uint32, dev int) (err error) {
	return Mknodat(AT_FDCWD, path, mode, dev)
}

func Open(path string, mode int, perm uint32) (fd int, err error) {
	return openat(AT_FDCWD, path, mode|O_LARGEFILE, perm)
}

//sys	openat(dirfd int, path string, flags int, mode uint32) (fd int, err error)

func Openat(dirfd int, path string, flags int, mode uint32) (fd int, err error) {
	return openat(dirfd, path, flags|O_LARGEFILE, mode)
}

//sys	openat2(dirfd int, path string, open_how *OpenHow, size int) (fd int, err error)

func Openat2(dirfd int, path string, how *OpenHow) (fd int, err error) {
	return openat2(dirfd, path, how, SizeofOpenHow)
}

func Pipe(p []int) error {
	return Pipe2(p, 0)
}

//sysnb	pipe2(p *[2]_C_int, flags int) (err error)

func Pipe2(p []int, flags int) error {
	if len(p) != 2 {
		return EINVAL
	}
	var pp [2]_C_int
	err := pipe2(&pp, flags)
	if err == nil {
		p[0] = int(pp[0])
		p[1] = int(pp[1])
	}
	return err
}

//sys	ppoll(fds *PollFd, nfds int, timeout *Timespec, sigmask *Sigset_t) (n int, err error)

func Ppoll(fds []PollFd, timeout *Timespec, sigmask *Sigset_t) (n int, err error) {
	if len(fds) == 0 {
		return ppoll(nil, 0, timeout, sigmask)
	}
	return ppoll(&fds[0], len(fds), timeout, sigmask)
}

func Poll(fds []PollFd, timeout int) (n int, err error) {
	var ts *Timespec
	if timeout >= 0 {
		ts = new(Timespec)
		*ts = NsecToTimespec(int64(timeout) * 1e6)
	}
	return Ppoll(fds, ts, nil)
}

//sys	Readlinkat(dirfd int, path string, buf []byte) (n int, err error)

func Readlink(path string, buf []byte) (n int, err error) {
	return Readlinkat(AT_FDCWD, path, buf)
}

func Rename(oldpath string, newpath string) (err error) {
	return Renameat(AT_FDCWD, oldpath, AT_FDCWD, newpath)
}

func Rmdir(path string) error {
	return Unlinkat(AT_FDCWD, path, AT_REMOVEDIR)
}

//sys	Symlinkat(oldpath string, newdirfd int, newpath string) (err error)

func Symlink(oldpath string, newpath string) (err error) {
	return Symlinkat(oldpath, AT_FDCWD, newpath)
}

func Unlink(path string) error {
	return Unlinkat(AT_FDCWD, path, 0)
}

//sys	Unlinkat(dirfd int, path string, flags int) (err error)

func Utimes(path string, tv []Timeval) error {
	if tv == nil {
		err := utimensat(AT_FDCWD, path, nil, 0)
		if err != ENOSYS {
			return err
		}
		return utimes(path, nil)
	}
	if len(tv) != 2 {
		return EINVAL
	}
	var ts [2]Timespec
	ts[0] = NsecToTimespec(TimevalToNsec(tv[0]))
	ts[1] = NsecToTimespec(TimevalToNsec(tv[1]))
	err := utimensat(AT_FDCWD, path, (*[2]Timespec)(unsafe.Pointer(&ts[0])), 0)
	if err != ENOSYS {
		return err
	}
	return utimes(path, (*[2]Timeval)(unsafe.Pointer(&tv[0])))
}

//sys	utimensat(dirfd int, path string, times *[2]Timespec, flags int) (err error)

func UtimesNano(path string, ts []Timespec) error {
	return UtimesNanoAt(AT_FDCWD, path, ts, 0)
}

func UtimesNanoAt(dirfd int, path string, ts []Timespec, flags int) error {
	if ts == nil {
		return utimensat(dirfd, path, nil, flags)
	}
	if len(ts) != 2 {
		return EINVAL
	}
	return utimensat(dirfd, path, (*[2]Timespec)(unsafe.Pointer(&ts[0])), flags)
}

func Futimesat(dirfd int, path string, tv []Timeval) error {
	if tv == nil {
		return futimesat(dirfd, path, nil)
	}
	if len(tv) != 2 {
		return EINVAL
	}
	return futimesat(dirfd, path, (*[2]Timeval)(unsafe.Pointer(&tv[0])))
}

func Futimes(fd int, tv []Timeval) (err error) {
	// Believe it or not, this is the best we can do on Linux
	// (and is what glibc does).
	return Utimes("/proc/self/fd/"+strconv.Itoa(fd), tv)
}

const ImplementsGetwd = true

//sys	Getcwd(buf []byte) (n int, err error)

func Getwd() (wd string, err error) {
	var buf [PathMax]byte
	n, err := Getcwd(buf[0:])
	if err != nil {
		return "", err
	}
	// Getcwd returns the number of bytes written to buf, including the NUL.
	if n < 1 || n > len(buf) || buf[n-1] != 0 {
		return "", EINVAL
	}
	// In some cases, Linux can return a path that starts with the
	// "(unreachable)" prefix, which can potentially be a valid relative
	// path. To work around that, return ENOENT if path is not absolute.
	if buf[0] != '/' {
		return "", ENOENT
	}

	return string(buf[0 : n-1]), nil
}

func Getgroups() (gids []int, err error) {
	n, err := getgroups(0, nil)
	if err != nil {
		return nil, err
	}
	if n == 0 {
		return nil, nil
	}

	// Sanity check group count. Max is 1<<16 on Linux.
	if n < 0 || n > 1<<20 {
		return nil, EINVAL
	}

	a := make([]_Gid_t, n)
	n, err = getgroups(n, &a[0])
	if err != nil {
		return nil, err
	}
	gids = make([]int, n)
	for i, v := range a[0:n] {
		gids[i] = int(v)
	}
	return
}

func Setgroups(gids []int) (err error) {
	if len(gids) == 0 {
		return setgroups(0, nil)
	}

	a := make([]_Gid_t, len(gids))
	for i, v := range gids {
		a[i] = _Gid_t(v)
	}
	return setgroups(len(a), &a[0])
}

type WaitStatus uint32

// Wait status is 7 bits at bottom, either 0 (exited),
// 0x7F (stopped), or a signal number that caused an exit.
// The 0x80 bit is whether there was a core dump.
// An extra number (exit code, signal causing a stop)
// is in the high bits. At least that's the idea.
// There are various irregularities. For example, the
// "continued" status is 0xFFFF, distinguishing itself
// from stopped via the core dump bit.

const (
	mask    = 0x7F
	core    = 0x80
	exited  = 0x00
	stopped = 0x7F
	shift   = 8
)

func (w WaitStatus) Exited() bool { return w&mask == exited }

func (w WaitStatus) Signaled() bool { return w&mask != stopped && w&mask != exited }

func (w WaitStatus) Stopped() bool { return w&0xFF == stopped }

func (w WaitStatus) Continued() bool { return w == 0xFFFF }

func (w WaitStatus) CoreDump() bool { return w.Signaled() && w&core != 0 }

func (w WaitStatus) ExitStatus() int {
	if !w.Exited() {
		return -1
	}
	return int(w>>shift) & 0xFF
}

func (w WaitStatus) Signal() syscall.Signal {
	if !w.Signaled() {
		return -1
	}
	return syscall.Signal(w & mask)
}

func (w WaitStatus) StopSignal() syscall.Signal {
	if !w.Stopped() {
		return -1
	}
	return syscall.Signal(w>>shift) & 0xFF
}

func (w WaitStatus) TrapCause() int {
	if w.StopSignal() != SIGTRAP {
		return -1
	}
	return int(w>>shift) >> 8
}

//sys	wait4(pid int, wstatus *_C_int, options int, rusage *Rusage) (wpid int, err error)

func Wait4(pid int, wstatus *WaitStatus, options int, rusage *Rusage) (wpid int, err error) {
	var status _C_int
	wpid, err = wait4(pid, &status, options, rusage)
	if wstatus != nil {
		*wstatus = WaitStatus(status)
	}
	return
}

//sys	Waitid(idType int, id int, info *Siginfo, options int, rusage *Rusage) (err error)

func Mkfifo(path string, mode uint32) error {
	return Mknod(path, mode|S_IFIFO, 0)
}

func Mkfifoat(dirfd int, path string, mode uint32) error {
	return Mknodat(dirfd, path, mode|S_IFIFO, 0)
}

func (sa *SockaddrInet4) sockaddr() (unsafe.Pointer, _Socklen, error) {
	if sa.Port < 0 || sa.Port > 0xFFFF {
		return nil, 0, EINVAL
	}
	sa.raw.Family = AF_INET
	p := (*[2]byte)(unsafe.Pointer(&sa.raw.Port))
	p[0] = byte(sa.Port >> 8)
	p[1] = byte(sa.Port)
	sa.raw.Addr = sa.Addr
	return unsafe.Pointer(&sa.raw), SizeofSockaddrInet4, nil
}

func (sa *SockaddrInet6) sockaddr() (unsafe.Pointer, _Socklen, error) {
	if sa.Port < 0 || sa.Port > 0xFFFF {
		return nil, 0, EINVAL
	}
	sa.raw.Family = AF_INET6
	p := (*[2]byte)(unsafe.Pointer(&sa.raw.Port))
	p[0] = byte(sa.Port >> 8)
	p[1] = byte(sa.Port)
	sa.raw.Scope_id = sa.ZoneId
	sa.raw.Addr = sa.Addr
	return unsafe.Pointer(&sa.raw), SizeofSockaddrInet6, nil
}

func (sa *SockaddrUnix) sockaddr() (unsafe.Pointer, _Socklen, error) {
	name := sa.Name
	n := len(name)
	if n >= len(sa.raw.Path) {
		return nil, 0, EINVAL
	}
	sa.raw.Family = AF_UNIX
	for i := 0; i < n; i++ {
		sa.raw.Path[i] = int8(name[i])
	}
	// length is family (uint16), name, NUL.
	sl := _Socklen(2)
	if n > 0 {
		sl += _Socklen(n) + 1
	}
	if sa.raw.Path[0] == '@' || (sa.raw.Path[0] == 0 && sl > 3) {
		// Check sl > 3 so we don't change unnamed socket behavior.
		sa.raw.Path[0] = 0
		// Don't count trailing NUL for abstract address.
		sl--
	}

	return unsafe.Pointer(&sa.raw), sl, nil
}

// SockaddrLinklayer implements the Sockaddr interface for AF_PACKET type sockets.
type SockaddrLinklayer struct {
	Protocol uint16
	Ifindex  int
	Hatype   uint16
	Pkttype  uint8
	Halen    uint8
	Addr     [8]byte
	raw      RawSockaddrLinklayer
}

func (sa *SockaddrLinklayer) sockaddr() (unsafe.Pointer, _Socklen, error) {
	if sa.Ifindex < 0 || sa.Ifindex > 0x7fffffff {
		return nil, 0, EINVAL
	}
	sa.raw.Family = AF_PACKET
	sa.raw.Protocol = sa.Protocol
	sa.raw.Ifindex = int32(sa.Ifindex)
	sa.raw.Hatype = sa.Hatype
	sa.raw.Pkttype = sa.Pkttype
	sa.raw.Halen = sa.Halen
	sa.raw.Addr = sa.Addr
	return unsafe.Pointer(&sa.raw), SizeofSockaddrLinklayer, nil
}

// SockaddrNetlink implements the Sockaddr interface for AF_NETLINK type sockets.
type SockaddrNetlink struct {
	Family uint16
	Pad    uint16
	Pid    uint32
	Groups uint32
	raw    RawSockaddrNetlink
}

func (sa *SockaddrNetlink) sockaddr() (unsafe.Pointer, _Socklen, error) {
	sa.raw.Family = AF_NETLINK
	sa.raw.Pad = sa.Pad
	sa.raw.Pid = sa.Pid
	sa.raw.Groups = sa.Groups
	return unsafe.Pointer(&sa.raw), SizeofSockaddrNetlink, nil
}

// SockaddrHCI implements the Sockaddr interface for AF_BLUETOOTH type sockets
// using the HCI protocol.
type SockaddrHCI struct {
	Dev     uint16
	Channel uint16
	raw     RawSockaddrHCI
}

func (sa *SockaddrHCI) sockaddr() (unsafe.Pointer, _Socklen, error) {
	sa.raw.Family = AF_BLUETOOTH
	sa.raw.Dev = sa.Dev
	sa.raw.Channel = sa.Channel
	return unsafe.Pointer(&sa.raw), SizeofSockaddrHCI, nil
}

// SockaddrL2 implements the Sockaddr interface for AF_BLUETOOTH type sockets
// using the L2CAP protocol.
type SockaddrL2 struct {
	PSM      uint16
	CID      uint16
	Addr     [6]uint8
	AddrType uint8
	raw      RawSockaddrL2
}

func (sa *SockaddrL2) sockaddr() (unsafe.Pointer, _Socklen, error) {
	sa.raw.Family = AF_BLUETOOTH
	psm := (*[2]byte)(unsafe.Pointer(&sa.raw.Psm))
	psm[0] = byte(sa.PSM)
	psm[1] = byte(sa.PSM >> 8)
	for i := 0; i < len(sa.Addr); i++ {
		sa.raw.Bdaddr[i] = sa.Addr[len(sa.Addr)-1-i]
	}
	cid := (*[2]byte)(unsafe.Pointer(&sa.raw.Cid))
	cid[0] = byte(sa.CID)
	cid[1] = byte(sa.CID >> 8)
	sa.raw.Bdaddr_type = sa.AddrType
	return unsafe.Pointer(&sa.raw), SizeofSockaddrL2, nil
}

// SockaddrRFCOMM implements the Sockaddr interface for AF_BLUETOOTH type sockets
// using the RFCOMM protocol.
//
// Server example:
//
//	fd, _ := Socket(AF_BLUETOOTH, SOCK_STREAM, BTPROTO_RFCOMM)
//	_ = unix.Bind(fd, &unix.SockaddrRFCOMM{
//		Channel: 1,
//		Addr:    [6]uint8{0, 0, 0, 0, 0, 0}, // BDADDR_ANY or 00:00:00:00:00:00
//	})
//	_ = Listen(fd, 1)
//	nfd, sa, _ := Accept(fd)
//	fmt.Printf("conn addr=%v fd=%d", sa.(*unix.SockaddrRFCOMM).Addr, nfd)
//	Read(nfd, buf)
//
// Client example:
//
//	fd, _ := Socket(AF_BLUETOOTH, SOCK_STREAM, BTPROTO_RFCOMM)
//	_ = Connect(fd, &SockaddrRFCOMM{
//		Channel: 1,
//		Addr:    [6]byte{0x11, 0x22, 0x33, 0xaa, 0xbb, 0xcc}, // CC:BB:AA:33:22:11
//	})
//	Write(fd, []byte(`hello`))
type SockaddrRFCOMM struct {
	// Addr represents a bluetooth address, byte ordering is little-endian.
	Addr [6]uint8

	// Channel is a designated bluetooth channel, only 1-30 are available for use.
	// Since Linux 2.6.7 and further zero value is the first available channel.
	Channel uint8

	raw RawSockaddrRFCOMM
}

func (sa *SockaddrRFCOMM) sockaddr() (unsafe.Pointer, _Socklen, error) {
	sa.raw.Family = AF_BLUETOOTH
	sa.raw.Channel = sa.Channel
	sa.raw.Bdaddr = sa.Addr
	return unsafe.Pointer(&sa.raw), SizeofSockaddrRFCOMM, nil
}

// SockaddrCAN implements the Sockaddr interface for AF_CAN type sockets.
// The RxID and TxID fields are used for transport protocol addressing in
// (CAN_TP16, CAN_TP20, CAN_MCNET, and CAN_ISOTP), they can be left with
// zero values for CAN_RAW and CAN_BCM sockets as they have no meaning.
//
// The SockaddrCAN struct must be bound to the socket file descriptor
// using Bind before the CAN socket can be used.
//
//	// Read one raw CAN frame
//	fd, _ := Socket(AF_CAN, SOCK_RAW, CAN_RAW)
//	addr := &SockaddrCAN{Ifindex: index}
//	Bind(fd, addr)
//	frame := make([]byte, 16)
//	Read(fd, frame)
//
// The full SocketCAN documentation can be found in the linux kernel
// archives at: https://www.kernel.org/doc/Documentation/networking/can.txt
type SockaddrCAN struct {
	Ifindex int
	RxID    uint32
	TxID    uint32
	raw     RawSockaddrCAN
}

func (sa *SockaddrCAN) sockaddr() (unsafe.Pointer, _Socklen, error) {
	if sa.Ifindex < 0 || sa.Ifindex > 0x7fffffff {
		return nil, 0, EINVAL
	}
	sa.raw.Family = AF_CAN
	sa.raw.Ifindex = int32(sa.Ifindex)
	rx := (*[4]byte)(unsafe.Pointer(&sa.RxID))
	for i := 0; i < 4; i++ {
		sa.raw.Addr[i] = rx[i]
	}
	tx := (*[4]byte)(unsafe.Pointer(&sa.TxID))
	for i := 0; i < 4; i++ {
		sa.raw.Addr[i+4] = tx[i]
	}
	return unsafe.Pointer(&sa.raw), SizeofSockaddrCAN, nil
}

// SockaddrCANJ1939 implements the Sockaddr interface for AF_CAN using J1939
// protocol (https://en.wikipedia.org/wiki/SAE_J1939). For more information
// on the purposes of the fields, check the official linux kernel documentation
// available here: https://www.kernel.org/doc/Documentation/networking/j1939.rst
type SockaddrCANJ1939 struct {
	Ifindex int
	Name    uint64
	PGN     uint32
	Addr    uint8
	raw     RawSockaddrCAN
}

func (sa *SockaddrCANJ1939) sockaddr() (unsafe.Pointer, _Socklen, error) {
	if sa.Ifindex < 0 || sa.Ifindex > 0x7fffffff {
		return nil, 0, EINVAL
	}
	sa.raw.Family = AF_CAN
	sa.raw.Ifindex = int32(sa.Ifindex)
	n := (*[8]byte)(unsafe.Pointer(&sa.Name))
	for i := 0; i < 8; i++ {
		sa.raw.Addr[i] = n[i]
	}
	p := (*[4]byte)(unsafe.Pointer(&sa.PGN))
	for i := 0; i < 4; i++ {
		sa.raw.Addr[i+8] = p[i]
	}
	sa.raw.Addr[12] = sa.Addr
	return unsafe.Pointer(&sa.raw), SizeofSockaddrCAN, nil
}

// SockaddrALG implements the Sockaddr interface for AF_ALG type sockets.
// SockaddrALG enables userspace access to the Linux kernel's cryptography
// subsystem. The Type and Name fields specify which type of hash or cipher
// should be used with a given socket.
//
// To create a file descriptor that provides access to a hash or cipher, both
// Bind and Accept must be used. Once the setup process is complete, input
// data can be written to the socket, processed by the kernel, and then read
// back as hash output or ciphertext.
//
// Here is an example of using an AF_ALG socket with SHA1 hashing.
// The initial socket setup process is as follows:
//
//	// Open a socket to perform SHA1 hashing.
//	fd, _ := unix.Socket(unix.AF_ALG, unix.SOCK_SEQPACKET, 0)
//	addr := &unix.SockaddrALG{Type: "hash", Name: "sha1"}
//	unix.Bind(fd, addr)
//	// Note: unix.Accept does not work at this time; must invoke accept()
//	// manually using unix.Syscall.
//	hashfd, _, _ := unix.Syscall(unix.SYS_ACCEPT, uintptr(fd), 0, 0)
//
// Once a file descriptor has been returned from Accept, it may be used to
// perform SHA1 hashing. The descriptor is not safe for concurrent use, but
// may be re-used repeatedly with subsequent Write and Read operations.
//
// When hashing a small byte slice or string, a single Write and Read may
// be used:
//
//	// Assume hashfd is already configured using the setup process.
//	hash := os.NewFile(hashfd, "sha1")
//	// Hash an input string and read the results. Each Write discards
//	// previous hash state. Read always reads the current state.
//	b := make([]byte, 20)
//	for i := 0; i < 2; i++ {
//	    io.WriteString(hash, "Hello, world.")
//	    hash.Read(b)
//	    fmt.Println(hex.EncodeToString(b))
//	}
//	// Output:
//	// 2ae01472317d1935a84797ec1983ae243fc6aa28
//	// 2ae01472317d1935a84797ec1983ae243fc6aa28
//
// For hashing larger byte slices, or byte streams such as those read from
// a file or socket, use Sendto with MSG_MORE to instruct the kernel to update
// the hash digest instead of creating a new one for a given chunk and finalizing it.
//
//	// Assume hashfd and addr are already configured using the setup process.
//	hash := os.NewFile(hashfd, "sha1")
//	// Hash the contents of a file.
//	f, _ := os.Open("/tmp/linux-4.10-rc7.tar.xz")
//	b := make([]byte, 4096)
//	for {
//	    n, err := f.Read(b)
//	    if err == io.EOF {
//	        break
//	    }
//	    unix.Sendto(hashfd, b[:n], unix.MSG_MORE, addr)
//	}
//	hash.Read(b)
//	fmt.Println(hex.EncodeToString(b))
//	// Output: 85cdcad0c06eef66f805ecce353bec9accbeecc5
//
// For more information, see: http://www.chronox.de/crypto-API/crypto/userspace-if.html.
type SockaddrALG struct {
	Type    string
	Name    string
	Feature uint32
	Mask    uint32
	raw     RawSockaddrALG
}

func (sa *SockaddrALG) sockaddr() (unsafe.Pointer, _Socklen, error) {
	// Leave room for NUL byte terminator.
	if len(sa.Type) > len(sa.raw.Type)-1 {
		return nil, 0, EINVAL
	}
	if len(sa.Name) > len(sa.raw.Name)-1 {
