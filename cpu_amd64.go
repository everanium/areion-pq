//go:build amd64 && !purego

package areionpq

import "golang.org/x/sys/cpu"

var (
	hasPCLMULQDQ  bool
	hasVPCLMULQDQ bool
	hasAVX2       bool
)

func cpuid(eaxArg, ecxArg uint32) (eax, ebx, ecx, edx uint32)

// hasVAESBit reads the VAES bit (CPUID leaf 7, ECX bit 9) directly.
// HasAVX2 implies that leaf 7 exists and that the OS saves YMM registers.
func hasVAESBit() bool {
	if !cpu.X86.HasAVX2 {
		return false
	}
	_, _, ecx7, _ := cpuid(7, 0)
	return ecx7&(1<<9) != 0
}

// hasVPCLMULBit reads the VPCLMULQDQ bit (CPUID leaf 7, ECX bit 10) directly.
func hasVPCLMULBit() bool {
	if !cpu.X86.HasAVX2 {
		return false
	}
	_, _, ecx7, _ := cpuid(7, 0)
	return ecx7&(1<<10) != 0
}

func probeCPU() (aesni, vex, armCrypto, vaesAVX2, avx512 bool) {
	hasPCLMULQDQ = cpu.X86.HasPCLMULQDQ
	hasVPCLMULQDQ = (cpu.X86.HasAVX && cpu.X86.HasPCLMULQDQ) || hasVPCLMULBit()
	hasAVX2 = cpu.X86.HasAVX2
	aesni = cpu.X86.HasAES
	vex = cpu.X86.HasAES && cpu.X86.HasAVX
	vaesAVX2 = hasVAESBit()
	avx512 = cpu.X86.HasAVX512F && cpu.X86.HasAVX512DQ && cpu.X86.HasAVX512BW && cpu.X86.HasAVX512VL && vaesAVX2
	return
}
