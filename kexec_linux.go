// package fit is for parsing flattened image tree binaries
package fit

type kexecSegment struct {
	buf		*[]byte
	bufsz		uint
	mem		uintptr
	memsz		uint
}

func kexecLoadSyscall(entry uint64, segments *[]kexecSegment, flags uintptr) (err error) {
	_, _, e := syscall.Syscall6(syscall.SYS_KEXEC_LOAD, uintptr(entry), uintptr(len(*segments)), uintptr(unsafe.Pointer(segments)), uintptr(flags))
	if e != 0 {
		err = errnoErr(e)
	}
	return
}

func (f *Fit) KexecLoadConfig(conf Config) {
	for _, image := range conf.ImageList {
		segment[i].buf = &image.Image.data
		segment[i].bufsz = len(image.Image.data)
		segment[i].mem = uintptr(image.Image.LoadAddr)
		segment[i].memsz = image.Image.LoadSize
	}

}
