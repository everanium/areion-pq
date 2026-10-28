//go:build (!amd64 && !arm64) || purego

package areionpq

import (
	"runtime/debug"
	"testing"
	"unsafe"
)

const (
	hasSIMDRegProbe       = false
	areionResidueGap      = 1 << 10
	areionResiduePad      = 2 << 10
	areionResidueWindow   = 16 << 10
	areionResidueSentinel = uint64(0x5A5A5A5A5A5A5A5A)
	areionSIMDWords       = 96
	areionStackWords      = areionResidueWindow / 8
	areionTotalWords      = areionStackWords + areionSIMDWords
)

func dirtySIMDRegForTest(masked uint64) {
	_ = masked
}

//go:noinline
func areionResidueGrow(i int) byte {
	var pad [4 * areionResidueWindow]byte
	pad[i] = 1
	return pad[(i+1)%len(pad)]
}

//go:noinline
//go:nocheckptr
func areionResidueProbe(fn func(), res []uint64) {
	var anchor uint64
	top := unsafe.Add(unsafe.Pointer(&anchor), -areionResidueGap)
	for i := range res {
		*(*uint64)(unsafe.Add(top, -8*(i+1))) = areionResidueSentinel
	}
	areionResidueDeep(fn, 0)
	for i := range res {
		res[i] = *(*uint64)(unsafe.Add(top, -8*(i+1)))
	}
}

//go:noinline
func areionResidueDeep(fn func(), i int) byte {
	var pad [areionResiduePad]byte
	pad[i] = 1
	fn()
	return pad[(i+7)%len(pad)]
}

//go:noinline
func captureAreionFrameAndRegResidue(call func(), dst *[areionTotalWords]uint64) int {
	defer debug.SetGCPercent(debug.SetGCPercent(-1))
	done := make(chan struct{})
	go func() {
		defer close(done)
		areionResidueGrow(0)
		clear(dst[areionStackWords:])
		areionResidueProbe(call, dst[:areionStackWords])
	}()
	<-done
	written := 0
	for i := 0; i < areionStackWords; i++ {
		if dst[i] != areionResidueSentinel {
			written++
		}
	}
	return written
}

func testAreionPQArchAsmKernels(t *testing.T, tier string, res *[areionTotalWords]uint64) {
	_ = t
	_ = tier
	_ = res
}
