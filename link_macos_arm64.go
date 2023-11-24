//go:build darwin && arm64

package silkworm_go

// #cgo LDFLAGS: -lsilkworm_capi
// #cgo LDFLAGS: -L${SRCDIR}/lib/macos_arm64
// #cgo LDFLAGS: -Wl,-rpath ${SRCDIR}/lib/macos_arm64
// #cgo LDFLAGS: -mmacosx-version-min=13.3
import "C"
