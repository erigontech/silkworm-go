//go:build linux && arm64

package silkworm_go

// #cgo LDFLAGS: -lsilkworm_capi
// #cgo LDFLAGS: -L${SRCDIR}/lib/linux_arm64
// #cgo LDFLAGS: -Wl,-rpath ${SRCDIR}/lib/linux_arm64
import "C"
