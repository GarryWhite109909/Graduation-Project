// Copyright 2020 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build zos && s390x

// Many of the following syscalls are not available on all versions of z/OS.
// Some missing calls have legacy implementations/simulations but others
// will be missing completely. To achieve consistent failing behaviour on
// legacy systems, we first test the function pointer via a safeloading
// mechanism to see if the function exists on a given system. Then execution
// is branched to either continue the function call, or return an error.

package unix

import (
	"bytes"
	"fmt"
	"os"
	"reflect"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"sync"
	"syscall"
	"unsafe"
)

//go:noescape
func initZosLibVec()

//go:noescape
func GetZosLibVec() uintptr

func init() {
	initZosLibVec()
	r0, _, _ := CallLeFuncWithPtrReturn(GetZosLibVec()+SYS_____GETENV_A<<4, uintptr(unsafe.Pointer(&([]byte("__ZOS_XSYSTRACE\x00"))[0])))
	if r0 != 0 {
		n, _, _ := CallLeFuncWithPtrReturn(GetZosLibVec()+SYS___ATOI_A<<4, r0)
		ZosTraceLevel = int(n)
		r0, _, _ := CallLeFuncWithPtrReturn(GetZosLibVec()+SYS_____GETENV_A<<4, uintptr(unsafe.Pointer(&([]byte("__ZOS_XSYSTRACEFD\x00"))[0])))
		if r0 != 0 {
			fd, _, _ := CallLeFuncWithPtrReturn(GetZosLibVec()+SYS___ATOI_A<<4, r0)
			f := os.NewFile(fd, "zostracefile")
			if f != nil {
				ZosTracefile = f
			}
		}

	}
}

//go:noescape
func CallLeFuncWithErr(funcdesc uintptr, parms ...uintptr) (ret, errno2 uintptr, err Errno)

//go:noescape
func CallLeFuncWithPtrReturn(funcdesc uintptr, parms ...uintptr) (ret, errno2 uintptr, err Errno)

// -------------------------------
// pointer validity test
// good pointer returns 0
// bad pointer returns 1
//
//go:nosplit
func ptrtest(uintptr) uint64

// Load memory at ptr location with error handling if the location is invalid
//
//go:noescape
func safeload(ptr uintptr) (value uintptr, error uintptr)

const (
	entrypointLocationOffset = 8 // From function descriptor

	xplinkEyecatcher   = 0x00c300c500c500f1 // ".C.E.E.1"
	eyecatcherOffset   = 16                 // From function entrypoint (negative)
	ppa1LocationOffset = 8                  // From function entrypoint (negative)

	nameLenOffset = 0x14 // From PPA1 start
	nameOffset    = 0x16 // From PPA1 start
)

func getPpaOffset(funcptr uintptr) int64 {
	entrypoint, err := safeload(funcptr + entrypointLocationOffset)
	if err != 0 {
		return -1
	}

	// XPLink functions have ".C.E.E.1" as the first 8 bytes (EBCDIC)
	val, err := safeload(entrypoint - eyecatcherOffset)
	if err != 0 {
		return -1
	}
	if val != xplinkEyecatcher {
		return -1
	}

	ppaoff, err := safeload(entrypoint - ppa1LocationOffset)
	if err != 0 {
		return -1
	}

	ppaoff >>= 32
	return int64(ppaoff)
}

//-------------------------------
// function descriptor pointer validity test
// good pointer returns 0
// bad pointer returns 1

// TODO: currently mksyscall_zos_s390x.go generate empty string for funcName
// have correct funcName pass to the funcptrtest function
func funcptrtest(funcptr uintptr, funcName string) uint64 {
	entrypoint, err := safeload(funcptr + entrypointLocationOffset)
	if err != 0 {
		return 1
	}

	ppaoff := getPpaOffset(funcptr)
	if ppaoff == -1 {
		return 1
	}

	// PPA1 offset value is from the start of the entire function block, not the entrypoint
	ppa1 := (entrypoint - eyecatcherOffset) + uintptr(ppaoff)

	nameLen, err := safeload(ppa1 + nameLenOffset)
	if err != 0 {
		return 1
	}

	nameLen >>= 48
	if nameLen > 128 {
		return 1
	}

	// no function name input to argument end here
	if funcName == "" {
		return 0
	}

	var funcname [128]byte
	for i := 0; i < int(nameLen); i += 8 {
		v, err := safeload(ppa1 + nameOffset + uintptr(i))
		if err != 0 {
			return 1
		}
		funcname[i] = byte(v >> 56)
		funcname[i+1] = byte(v >> 48)
		funcname[i+2] = byte(v >> 40)
		funcname[i+3] = byte(v >> 32)
		funcname[i+4] = byte(v >> 24)
		funcname[i+5] = byte(v >> 16)
		funcname[i+6] = byte(v >> 8)
		funcname[i+7] = byte(v)
	}

	runtime.CallLeFuncByPtr(runtime.XplinkLibvec+SYS___E2A_L<<4, // __e2a_l
		[]uintptr{uintptr(unsafe.Pointer(&funcname[0])), nameLen})

	name := string(funcname[:nameLen])
	if name != funcName {
		return 1
	}

	return 0
}

// For detection of capabilities on a system.
// Is function descriptor f a valid function?
func isValidLeFunc(f uintptr) error {
	ret := funcptrtest(f, "")
	if ret != 0 {
		return fmt.Errorf("Bad pointer, not an LE function ")
	}
	return nil
}

// Retrieve function name from descriptor
func getLeFuncName(f uintptr) (string, error) {
	// assume it has been checked, only check ppa1 validity here
	entry := ((*[2]uintptr)(unsafe.Pointer(f)))[1]
	preamp := ((*[4]uint32)(unsafe.Pointer(entry - eyecatcherOffset)))

	offsetPpa1 := preamp[2]
	if offsetPpa1 > 0x0ffff {
		return "", fmt.Errorf("PPA1 offset seems too big 0x%x\n", offsetPpa1)
	}

	ppa1 := uintptr(unsafe.Pointer(preamp)) + uintptr(offsetPpa1)
	res := ptrtest(ppa1)
	if res != 0 {
		return "", fmt.Errorf("PPA1 address not valid")
	}

	size := *(*uint16)(unsafe.Pointer(ppa1 + nameLenOffset))
	if size > 128 {
		return "", fmt.Errorf("Function name seems too long, length=%d\n", size)
	}

	var name [128]byte
	funcname := (*[128]byte)(unsafe.Pointer(ppa1 + nameOffset))
	copy(name[0:size], funcname[0:size])

	runtime.CallLeFuncByPtr(runtime.XplinkLibvec+SYS___E2A_L<<4, // __e2a_l
		[]uintptr{uintptr(unsafe.Pointer(&name[0])), uintptr(size)})

	return string(name[:size]), nil
}

// Check z/OS version
func zosLeVersion() (version, release uint32) {
	p1 := (*(*uintptr)(unsafe.Pointer(uintptr(1208)))) >> 32
	p1 = *(*uintptr)(unsafe.Pointer(uintptr(p1 + 88)))
	p1 = *(*uintptr)(unsafe.Pointer(uintptr(p1 + 8)))
	p1 = *(*uintptr)(unsafe.Pointer(uintptr(p1 + 984)))
	vrm := *(*uint32)(unsafe.Pointer(p1 + 80))
	version = (vrm & 0x00ff0000) >> 16
	release = (vrm & 0x0000ff00) >> 8
	return
}

// returns a zos C FILE * for stdio fd 0, 1, 2
func ZosStdioFilep(fd int32) uintptr {
	return uintptr(*(*uint64)(unsafe.Pointer(uintptr(*(*uint64)(unsafe.Pointer(uintptr(*(*uint64)(unsafe.Pointer(uintptr(uint64(*(*uint32)(unsafe.Pointer(uintptr(1208)))) + 80))) + uint64((fd+2)<<3))))))))
}

func copyStat(stat *Stat_t, statLE *Stat_LE_t) {
	stat.Dev = uint64(statLE.Dev)
	stat.Ino = uint64(statLE.Ino)
	stat.Nlink = uint64(statLE.Nlink)
	stat.Mode = uint32(statLE.Mode)
	stat.Uid = uint32(statLE.Uid)
	stat.Gid = uint32(statLE.Gid)
	stat.Rdev = uint64(statLE.Rdev)
	stat.Size = statLE.Size
	stat.Atim.Sec = int64(statLE.Atim)
	stat.Atim.Nsec = 0 //zos doesn't return nanoseconds
	stat.Mtim.Sec = int64(statLE.Mtim)
	stat.Mtim.Nsec = 0 //zos doesn't return nanoseconds
	stat.Ctim.Sec = int64(statLE.Ctim)
	stat.Ctim.Nsec = 0 //zos doesn't return nanoseconds
	stat.Blksize = int64(statLE.Blksize)
	stat.Blocks = statLE.Blocks
}

func svcCall(fnptr unsafe.Pointer, argv *unsafe.Pointer, dsa *uint64)
func svcLoad(name *byte) unsafe.Pointer
func svcUnload(name *byte, fnptr unsafe.Pointer) int64

func (d *Dirent) NameString() string {
	if d == nil {
		return ""
	}
	s := string(d.Name[:])
	idx := strings.IndexByte(s, 0)
	if idx == -1 {
		return s
	} else {
		return s[:idx]
	}
}

func DecodeData(dest []byte, sz int, val uint64) {
	for i := 0; i < sz; i++ {
		dest[sz-1-i] = byte((val >> (uint64(i * 8))) & 0xff)
	}
}

func EncodeData(data []byte) uint64 {
	var value uint64
	sz := len(data)
	for i := 0; i < sz; i++ {
		value |= uint64(data[i]) << uint64(((sz - i - 1) * 8))
	}
	return value
}

func (sa *SockaddrInet4) sockaddr() (unsafe.Pointer, _Socklen, error) {
	if sa.Port < 0 || sa.Port > 0xFFFF {
		return nil, 0, EINVAL
	}
	sa.raw.Len = SizeofSockaddrInet4
	sa.raw.Family = AF_INET
	p := (*[2]byte)(unsafe.Pointer(&sa.raw.Port))
	p[0] = byte(sa.Port >> 8)
	p[1] = byte(sa.Port)
	for i := 0; i < len(sa.Addr); i++ {
		sa.raw.Addr[i] = sa.Addr[i]
	}
	return unsafe.Pointer(&sa.raw), _Socklen(sa.raw.Len), nil
}

func (sa *SockaddrInet6) sockaddr() (unsafe.Pointer, _Socklen, error) {
	if sa.Port < 0 || sa.Port > 0xFFFF {
		return nil, 0, EINVAL
	}
	sa.raw.Len = SizeofSockaddrInet6
	sa.raw.Family = AF_INET6
	p := (*[2]byte)(unsafe.Pointer(&sa.raw.Port))
	p[0] = byte(sa.Port >> 8)
	p[1] = byte(sa.Port)
	sa.raw.Scope_id = sa.ZoneId
	for i := 0; i < len(sa.Addr); i++ {
		sa.raw.Addr[i] = sa.Addr[i]
	}
	return unsafe.Pointer(&sa.raw), _Socklen(sa.raw.Len), nil
}

func (sa *SockaddrUnix) sockaddr() (unsafe.Pointer, _Socklen, error) {
	name := sa.Name
	n := len(name)
	if n >= len(sa.raw.Path) || n == 0 {
		return nil, 0, EINVAL
	}
	sa.raw.Len = byte(3 + n) // 2 for Family, Len; 1 for NUL
	sa.raw.Family = AF_UNIX
	for i := 0; i < n; i++ {
		sa.raw.Path[i] = int8(name[i])
	}
	return unsafe.Pointer(&sa.raw), _Socklen(sa.raw.Len), nil
}

func anyToSockaddr(_ int, rsa *RawSockaddrAny) (Sockaddr, error) {
	// TODO(neeilan): Implement use of first param (fd)
	switch rsa.Addr.Family {
	case AF_UNIX:
		pp := (*RawSockaddrUnix)(unsafe.Pointer(rsa))
		sa := new(SockaddrUnix)
		// For z/OS, only replace NUL with @ when the
		// length is not zero.
		if pp.Len != 0 && pp.Path[0] == 0 {
			// "Abstract" Unix domain socket.
			// Rewrite leading NUL as @ for textual display.
			// (This is the standard convention.)
			// Not friendly to overwrite in place,
			// but the callers below don't care.
			pp.Path[0] = '@'
		}

		// Assume path ends at NUL.
		//
		// For z/OS, the length of the name is a field
		// in the structure. To be on the safe side, we
		// will still scan the name for a NUL but only
		// to the length provided in the structure.
		//
		// This is not technically the Linux semantics for
		// abstract Unix domain sockets--they are supposed
		// to be uninterpreted fixed-size binary blobs--but
		// everyone uses this convention.
		n := 0
		for n < int(pp.Len) && pp.Path[n] != 0 {
			n++
		}
		sa.Name = string(unsafe.Slice((*byte)(unsafe.Pointer(&pp.Path[0])), n))
		return sa, nil

	case AF_INET:
		pp := (*RawSockaddrInet4)(unsafe.Pointer(rsa))
		sa := new(SockaddrInet4)
		p := (*[2]byte)(unsafe.Pointer(&pp.Port))
		sa.Port = int(p[0])<<8 + int(p[1])
		for i := 0; i < len(sa.Addr); i++ {
			sa.Addr[i] = pp.Addr[i]
		}
		return sa, nil

	case AF_INET6:
		pp := (*RawSockaddrInet6)(unsafe.Pointer(rsa))
		sa := new(SockaddrInet6)
		p := (*[2]byte)(unsafe.Pointer(&pp.Port))
		sa.Port = int(p[0])<<8 + int(p[1])
		sa.ZoneId = pp.Scope_id
		for i := 0; i < len(sa.Addr); i++ {
			sa.Addr[i] = pp.Addr[i]
		}
		return sa, nil
	}
	return nil, EAFNOSUPPORT
}

func Accept(fd int) (nfd int, sa Sockaddr, err error) {
	var rsa RawSockaddrAny
	var len _Socklen = SizeofSockaddrAny
	nfd, err = accept(fd, &rsa, &len)
	if err != nil {
		return
	}
	// TODO(neeilan): Remove 0 in call
	sa, err = anyToSockaddr(0, &rsa)
	if err != nil {
		Close(nfd)
		nfd = 0
	}
	return
}

func Accept4(fd int, flags int) (nfd int, sa Sockaddr, err error) {
	var rsa RawSockaddrAny
	var len _Socklen = SizeofSockaddrAny
	nfd, err = accept4(fd, &rsa, &len, flags)
	if err != nil {
		return
	}
	if len > SizeofSockaddrAny {
		panic("RawSockaddrAny too small")
	}
	// TODO(neeilan): Remove 0 in call
	sa, err = anyToSockaddr(0, &rsa)
	if err != nil {
		Close(nfd)
		nfd = 0
	}
	return
}

func Ctermid() (tty string, err error) {
	var termdev [1025]byte
	runtime.EnterSyscall()
	r0, err2, err1 := CallLeFuncWithPtrReturn(GetZosLibVec()+SYS___CTERMID_A<<4, uintptr(unsafe.Pointer(&termdev[0])))
	runtime.ExitSyscall()
	if r0 == 0 {
		return "", fmt.Errorf("%s (errno2=0x%x)\n", err1.Error(), err2)
	}
	s := string(termdev[:])
	idx := strings.Index(s, string(rune(0)))
	if idx == -1 {
		tty = s
	} else {
		tty = s[:idx]
	}
	return
}

func (iov *Iovec) SetLen(length int) {
	iov.Len = uint64(length)
}

func (msghdr *Msghdr) SetControllen(length int) {
	msghdr.Controllen = int32(length)
}

func (cmsg *Cmsghdr) SetLen(length int) {
	cmsg.Len = int32(length)
}

//sys   fcntl(fd int, cmd int, arg int) (val int, err error)
//sys   Flistxattr(fd int, dest []byte) (sz int, err error) = SYS___FLISTXATTR_A
//sys   Fremovexattr(fd int, attr string) (err error) = SYS___FREMOVEXATTR_A
//sys	read(fd int, p []byte) (n int, err error)
//sys	write(fd int, p []byte) (n int, err error)

//sys   Fgetxattr(fd int, attr string, dest []byte) (sz int, err error) = SYS___FGETXATTR_A
//sys   Fsetxattr(fd int, attr string, data []byte, flag int) (err error) = SYS___FSETXATTR_A

//sys	accept(s int, rsa *RawSockaddrAny, addrlen *_Socklen) (fd int, err error) = SYS___ACCEPT_A
//sys	accept4(s int, rsa *RawSockaddrAny, addrlen *_Socklen, flags int) (fd int, err error) = SYS___ACCEPT4_A
//sys	bind(s int, addr unsafe.Pointer, addrlen _Socklen) (err error) = SYS___BIND_A
//sys	connect(s int, addr unsafe.Pointer, addrlen _Socklen) (err error) = SYS___CONNECT_A
//sysnb	getgroups(n int, list *_Gid_t) (nn int, err error)
//sysnb	setgroups(n int, list *_Gid_t) (err error)
//sys	getsockopt(s int, level int, name int, val unsafe.Pointer, vallen *_Socklen) (err error)
//sys	setsockopt(s int, level int, name int, val unsafe.Pointer, vallen uintptr) (err error)
//sysnb	socket(domain int, typ int, proto int) (fd int, err error)
//sysnb	socketpair(domain int, typ int, proto int, fd *[2]int32) (err error)
//sysnb	getpeername(fd int, rsa *RawSockaddrAny, addrlen *_Socklen) (err error) = SYS___GETPEERNAME_A
//sysnb	getsockname(fd int, rsa *RawSockaddrAny, addrlen *_Socklen) (err error) = SYS___GETSOCKNAME_A
//sys   Removexattr(path string, attr string) (err error) = SYS___REMOVEXATTR_A
//sys	recvfrom(fd int, p []byte, flags int, from *RawSockaddrAny, fromlen *_Socklen) (n int, err error) = SYS___RECVFROM_A
//sys	sendto(s int, buf []byte, flags int, to unsafe.Pointer, addrlen _Socklen) (err error) = SYS___SENDTO_A
//sys	recvmsg(s int, msg *Msghdr, flags int) (n int, err error) = SYS___RECVMSG_A
//sys	sendmsg(s int, msg *Msghdr, flags int) (n int, err error) = SYS___SENDMSG_A
//sys   mmap(addr uintptr, length uintptr, prot int, flag int, fd int, pos int64) (ret uintptr, err error) = SYS_MMAP
//sys   munmap(addr uintptr, length uintptr) (err error) = SYS_MUNMAP
//sys   ioctl(fd int, req int, arg uintptr) (err error) = SYS_IOCTL
//sys   ioctlPtr(fd int, req int, arg unsafe.Pointer) (err error) = SYS_IOCTL
//sys	shmat(id int, addr uintptr, flag int) (ret uintptr, err error) = SYS_SHMAT
//sys	shmctl(id int, cmd int, buf *SysvShmDesc) (result int, err error) = SYS_SHMCTL64
//sys	shmdt(addr uintptr) (err error) = SYS_SHMDT
//sys	shmget(key int, size int, flag int) (id int, err error) = SYS_SHMGET

//sys   Access(path string, mode uint32) (err error) = SYS___ACCESS_A
//sys   Chdir(path string) (err error) = SYS___CHDIR_A
//sys	Chown(path string, uid int, gid int) (err error) = SYS___CHOWN_A
//sys	Chmod(path string, mode uint32) (err error) = SYS___CHMOD_A
//sys   Creat(path string, mode uint32) (fd int, err error) = SYS___CREAT_A
//sys	Dup(oldfd int) (fd int, err error)
//sys	Dup2(oldfd int, newfd int) (err error)
//sys	Dup3(oldfd int, newfd int, flags int) (err error) = SYS_DUP3
//sys	Dirfd(dirp uintptr) (fd int, err error) = SYS_DIRFD
//sys	EpollCreate(size int) (fd int, err error) = SYS_EPOLL_CREATE
//sys	EpollCreate1(flags int) (fd int, err error) = SYS_EPOLL_CREATE1
//sys	EpollCtl(epfd int, op int, fd int, event *EpollEvent) (err error) = SYS_EPOLL_CTL
//sys	EpollPwait(epfd int, events []EpollEvent, msec int, sigmask *int) (n int, err error) = SYS_EPOLL_PWAIT
//sys	EpollWait(epfd int, events []EpollEvent, msec int) (n int, err error) = SYS_EPOLL_WAIT
//sys	Errno2() (er2 int) = SYS___ERRNO2
//sys	Eventfd(initval uint, flags int) (fd int, err error) = SYS_EVENTFD
//sys	Exit(code int)
//sys	Faccessat(dirfd int, path string, mode uint32, flags int) (err error) = SYS___FACCESSAT_A

func Faccessat2(dirfd int, path string, mode uint32, flags int) (err error) {
	return Faccessat(dirfd, path, mode, flags)
}

//sys	Fchdir(fd int) (err error)
//sys	Fchmod(fd int, mode uint32) (err error)
//sys	Fchmodat(dirfd int, path string, mode uint32, flags int) (err error) = SYS___FCHMODAT_A
//sys	Fchown(fd int, uid int, gid int) (err error)
//sys	Fchownat(fd int, path string, uid int, gid int, flags int) (err error) = SYS___FCHOWNAT_A
//sys	FcntlInt(fd uintptr, cmd int, arg int) (retval int, err error) = SYS_FCNTL
//sys	Fdatasync(fd int) (err error) = SYS_FDATASYNC
//sys	fstat(fd int, stat *Stat_LE_t) (err error)
//sys	fstatat(dirfd int, path string, stat *Stat_LE_t, flags int) (err error) = SYS___FSTATAT_A

func Fstat(fd int, stat *Stat_t) (err error) {
	var statLE Stat_LE_t
	err = fstat(fd, &statLE)
	copyStat(stat, &statLE)
	return
}

func Fstatat(dirfd int, path string, stat *Stat_t, flags int) (err error) {
	var statLE Stat_LE_t
	err = fstatat(dirfd, path, &statLE, flags)
	copyStat(stat, &statLE)
	return
}

func impl_Getxattr(path string, attr string, dest []byte) (sz int, err error) {
	var _p0 *byte
	_p0, err = BytePtrFromString(path)
	if err != nil {
		return
	}
	var _p1 *byte
	_p1, err = BytePtrFromString(attr)
	if err != nil {
		return
	}
	var _p2 unsafe.Pointer
	if len(dest) > 0 {
		_p2 = unsafe.Pointer(&dest[0])
	} else {
		_p2 = unsafe.Pointer(&_zero)
	}
	r0, e2, e1 := CallLeFuncWithErr(GetZosLibVec()+SYS___GETXATTR_A<<4, uintptr(unsafe.Pointer(_p0)), uintptr(unsafe.Pointer(_p1)), uintptr(_p2), uintptr(len(dest)))
	sz = int(r0)
	if int64(r0) == -1 {
		err = errnoErr2(e1, e2)
	}
	return
}

//go:nosplit
func get_GetxattrAddr() *(func(path string, attr string, dest []byte) (sz int, err error))

var Getxattr = enter_Getxattr

func enter_Getxattr(path string, attr string, dest []byte) (sz int, err error) {
	funcref := get_GetxattrAddr()
	if validGetxattr() {
		*funcref = impl_Getxattr
	} else {
		*funcref = error_Getxattr
	}
	return (*funcref)(path, attr, dest)
}

func error_Getxattr(path string, attr string, dest []byte) (sz int, err error) {
	return -1, ENOSYS
}

func validGetxattr() bool {
	if funcptrtest(GetZosLibVec()+SYS___GETXATTR_A<<4, "") == 0 {
		if name, err := getLeFuncName(GetZosLibVec() + SYS___GETXATTR_A<<4); err == nil {
			return name == "__getxattr_a"
		}
	}
	return false
}

//sys   Lgetxattr(link string, attr string, dest []byte) (sz int, err error) = SYS___LGETXATTR_A
//sys   Lsetxattr(path string, attr string, data []byte, flags int) (err error) = SYS___LSETXATTR_A

func impl_Setxattr(path string, attr string, data []byte, flags int) (err error) {
	var _p0 *byte
	_p0, err = BytePtrFromString(path)
	if err != nil {
		return
	}
	var _p1 *byte
	_p1, err = BytePtrFromString(attr)
	if err != nil {
		return
	}
	var _p2 unsafe.Pointer
	if len(data) > 0 {
		_p2 = unsafe.Pointer(&data[0])
	} else {
		_p2 = unsafe.Pointer(&_zero)
	}
	r0, e2, e1 := CallLeFuncWithErr(GetZosLibVec()+SYS___SETXATTR_A<<4, uintptr(unsafe.Pointer(_p0)), uintptr(unsafe.Pointer(_p1)), uintptr(_p2), uintptr(len(data)), uintptr(flags))
	if int64(r0) == -1 {
		err = errnoErr2(e1, e2)
	}
	return
}

//go:nosplit
func get_SetxattrAddr() *(func(path string, attr string, data []byte, flags int) (err error))

var Setxattr = enter_Setxattr

func enter_Setxattr(path string, attr string, data []byte, flags int) (err error) {
	funcref := get_SetxattrAddr()
	if validSetxattr() {
		*funcref = impl_Setxattr
	} else {
		*funcref = error_Setxattr
	}
	return (*funcref)(path, attr, data, flags)
}

func error_Setxattr(path string, attr string, data []byte, flags int) (err error) {
	return ENOSYS
}

func validSetxattr() bool {
	if funcptrtest(GetZosLibVec()+SYS___SETXATTR_A<<4, "") == 0 {
		if name, err := getLeFuncName(GetZosLibVec() + SYS___SETXATTR_A<<4); err == nil {
			return name == "__setxattr_a"
		}
	}
	return false
}

//sys	Fstatfs(fd int, buf *Statfs_t) (err error) = SYS_FSTATFS
//sys	Fstatvfs(fd int, stat *Statvfs_t) (err error) = SYS_FSTATVFS
//sys	Fsync(fd int) (err error)
//sys	Futimes(fd int, tv []Timeval) (err error) = SYS_FUTIMES
//sys	Futimesat(dirfd int, path string, tv []Timeval) (err error) = SYS___FUTIMESAT_A
//sys	Ftruncate(fd int, length int64) (err error)
//sys	Getrandom(buf []byte, flag