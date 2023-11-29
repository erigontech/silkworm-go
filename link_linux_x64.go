//go:build !nosilkworm && linux && amd64

package silkworm_go

// #cgo LDFLAGS: -lsilkworm_capi
// #cgo LDFLAGS: -L${SRCDIR}/lib/linux_x64
// #cgo LDFLAGS: -Wl,-rpath ${SRCDIR}/lib/linux_x64
import "C"
