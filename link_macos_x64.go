//go:build !nosilkworm && darwin && amd64

package silkworm_go

// #cgo LDFLAGS: -lsilkworm_capi
// #cgo LDFLAGS: -L${SRCDIR}/lib/macos_x64
// #cgo LDFLAGS: -Wl,-rpath ${SRCDIR}/lib/macos_x64
// #cgo LDFLAGS: -mmacosx-version-min=13.3
import "C"
