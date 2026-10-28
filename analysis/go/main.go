// Command analysis runs the Go empirical verification suite for areion-pq:
// witness extraction and Round 9 free-S-box soundness, SLH-DSA-Areion tweakable
// hash avalanche and shift-collision resistance, and QuickSilver VOLE gate
// verification plus TEM2-SIV tag sensitivity.
//
//	go run ./analysis/go <witness|slh|vole|all> [quick]
package main

import (
	"fmt"
	"os"
)

const usage = `usage: go run ./analysis/go <subcommand> [quick]

subcommands:
  witness [quick]   100,000 random witness extractions + exhaustive single-bit soundness
  slh     [quick]   SLHF128/256/TEM256, SLHH128/256, SLHPRF256 avalanche & shift-collision check
  vole    [quick]   GF(2^128)/GF(2^256) QuickSilver VOLE gate check & TEM2-SIV tag sensitivity
  all     [quick]   run all Go checks sequentially
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	quick := len(os.Args) >= 3 && (os.Args[2] == "quick" || os.Args[2] == "--quick")
	switch os.Args[1] {
	case "witness":
		runWitnessCheck(quick)
	case "slh":
		runSLHCollisionCheck(quick)
	case "vole":
		runVOLECheck(quick)
	case "all":
		runWitnessCheck(quick)
		runSLHCollisionCheck(quick)
		runVOLECheck(quick)
	default:
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
}
