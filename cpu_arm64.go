//go:build arm64 && !purego

package areionpq

import "golang.org/x/sys/cpu"

var hasPMULL bool

func probeCPU() (aesni, vex, armCrypto, vaesAVX2, avx512 bool) {
	armCrypto = cpu.ARM64.HasAES
	hasPMULL = cpu.ARM64.HasPMULL
	return
}
