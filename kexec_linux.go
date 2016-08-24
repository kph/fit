// package fit is for parsing flattened image tree binaries
package fit

import (
       "syscall"
       "unsafe"
)

type kexecSegment struct {
	buf		*[]byte
	bufsz		uint
	mem		uintptr
	memsz		uint
}

func kexecLoadSyscall(entry uint64, segments *[]kexecSegment, flags uintptr) (err error) {
	_, _, e := syscall.Syscall6(syscall.SYS_KEXEC_LOAD, uintptr(entry), uintptr(len(*segments)), uintptr(unsafe.Pointer(segments)), uintptr(flags), uintptr(0), uintptr(0))
	err = nil
	if e != 0 {
		err = e
	}
	return
}

func (f *Fit) KexecLoadConfig(conf Config) (err error) {
	var segments []kexecSegment

	segments = make([]kexecSegment, len(conf.ImageList), len(conf.ImageList))

	for i, image := range conf.ImageList {
		segments[i].buf = &image.Image.Data
		segments[i].bufsz = uint(len(image.Image.Data))
		segments[i].mem = uintptr(image.LoadAddr)
		segments[i].memsz = uint(image.LoadSize)
	}

	err = kexecLoadSyscall(conf.BaseAddr, &segments, uintptr(0))

	return
}
