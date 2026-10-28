//go:build (!amd64 && !arm64) || purego

package areionpq

func probeCPU() (aesni, vex, armCrypto, vaesAVX2, avx512 bool) {
	return false, false, false, false, false
}
