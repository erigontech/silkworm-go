package silkworm_go

// #include <stdlib.h>
import "C"

import (
	"runtime"
	"unsafe"
)

type CString struct {
	Data unsafe.Pointer
}

func NewCString(s string) *CString {
	cs := new(CString)
	cs.Data = unsafe.Pointer(C.CString(s))
	runtime.SetFinalizer(cs, func(cs *CString) { C.free(cs.Data) })
	return cs
}
