#!/usr/bin/env python3
"""Runs the cryptanalytic and algebraic verification suite for areion-pq.
Every check prints its result to stdout; with --record the output is also
written to analysis/results/<check>.txt (or <check>_quick.txt with --quick),
headed by the command that produced it.

    python3 analysis/run.py list
    python3 analysis/run.py <check> [--quick] [--record]
    python3 analysis/run.py all [--quick] [--record]
    python3 analysis/run.py clean

Requirements: Go (the module's own version), Python 3.9 or later, and for the
integral check a C compiler, make, and an x86-64 CPU with AES-NI + PCLMULQDQ.
"""

import argparse
import os
import platform
import shutil
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
BUILD = HERE / "build"
PY = HERE / "py"
RESULTS = HERE / "results"
GOBIN = BUILD / "analysis"
CBIN = BUILD / "pq_integral"


def sh(cmd, out, stdin=None, env=None):
    """Run cmd, echo and collect its stdout; fail on a non-zero exit."""
    cmd = [str(c) for c in cmd]
    p = subprocess.run(cmd, cwd=ROOT, stdin=stdin, capture_output=True, text=True, env=env)
    out.append(p.stdout)
    sys.stdout.write(p.stdout)
    sys.stdout.flush()
    if p.returncode != 0:
        sys.stderr.write(p.stderr)
        raise SystemExit(f"command failed ({p.returncode}): {' '.join(map(str, cmd))}")
    return p.stdout


def py(script, *args):
    return [sys.executable, str(PY / script), *map(str, args)]


def go(*args):
    return [str(GOBIN), *map(str, args)]


def have_aesni_pclmul():
    try:
        flags = open("/proc/cpuinfo").read().split()
    except OSError:
        flags = []
    return platform.machine() in ("x86_64", "AMD64") and "aes" in flags and "pclmulqdq" in flags


def prepare(need_go=False, need_c=False):
    BUILD.mkdir(exist_ok=True)
    if need_go:
        tmp = BUILD / f"analysis.{os.getpid()}.tmp"
        subprocess.run(["go", "build", "-o", str(tmp), "./analysis/go"], cwd=ROOT, check=True)
        os.replace(tmp, GOBIN)
    if need_c:
        if not have_aesni_pclmul():
            raise SystemExit("integral check needs an x86-64 CPU with AES-NI and PCLMULQDQ")
        subprocess.run(["make", "-s", "-C", str(HERE / "c"), f"BUILD={BUILD}"], check=True)


# ---------- checks ----------

def c_rank(q, out):
    sh(py("round9_witness_rank.py"), out)


def c_sbox_qs(q, out):
    sh(py("quicksilver_sbox_soundness.py"), out)


def c_ortho(q, out):
    sh(py("orthomorphism_bijectivity.py"), out)


def c_tweak(q, out):
    sh(py("slh_tweak_separation.py"), out)


def c_bounds(q, out):
    sh(py("pq_bounds_comparison.py"), out)


def c_witness(q, out):
    sh(go("witness", *(["quick"] if q else [])), out)


def c_slh(q, out):
    sh(go("slh", *(["quick"] if q else [])), out)


def c_vole(q, out):
    sh(go("vole", *(["quick"] if q else [])), out)


def c_integral(q, out):
    sh([str(CBIN), *(["quick"] if q else [])], out)


CHECKS = {
    # name: (fn, need_go, need_c, description, full_time, quick_time)
    "rank": (
        c_rank,
        False,
        False,
        "symbolic GF(2) Jacobian & rank of the 288/576/672-S-box free-round theorem (A)",
        "4 s",
        "4 s",
    ),
    "sbox_qs": (
        c_sbox_qs,
        False,
        False,
        "exhaustive 65,536-pair GF(2^8) QuickSilver degree-2 S-box completeness & soundness (B)",
        "10 s",
        "10 s",
    ),
    "ortho": (
        c_ortho,
        False,
        False,
        "GF(2)^256 orthomorphism rank & determinant for MulOrtho256 and OrthoSigma256 (C)",
        "2 s",
        "2 s",
    ),
    "tweak": (
        c_tweak,
        False,
        False,
        "SLH-DSA-Areion tweak-cancellation rank audit & IPM multi-target bounds (D)",
        "1 s",
        "1 s",
    ),
    "bounds": (
        c_bounds,
        False,
        False,
        "exact witness sizes, BAVC/GGM signature sizes, S-box counts & security margins (E)",
        "1 s",
        "1 s",
    ),
    "witness": (
        c_witness,
        True,
        False,
        "100,000 random P1/P2/EM2 witness extractions & exhaustive 1-bit soundness (F)",
        "3 s",
        "1 s",
    ),
    "slh": (
        c_slh,
        True,
        False,
        "SLHF128/256/TEM256, SLHH128/256, SLHPRF256 avalanche, chi^2 & shift-collision check (G)",
        "10 s",
        "3 s",
    ),
    "vole": (
        c_vole,
        True,
        False,
        "GF(2^128) QuickSilver VOLE gate check & TEM2-SIV tag sensitivity / forgery zeroization (H)",
        "4 s",
        "1 s",
    ),
    "integral": (
        c_integral,
        False,
        True,
        "AES-NI + PCLMULQDQ Lambda-set zero-sum balance of SLHF & QuickSilver GF(2^128) MACs (I)",
        "1 s",
        "1 s",
    ),
}


def run(name, quick, record):
    fn, need_go, need_c, desc, _, _ = CHECKS[name]
    header = f"$ python3 analysis/run.py {name}{' --quick' if quick else ''}\n"
    print(f"== {name}: {desc}", flush=True)
    prepare(need_go=need_go, need_c=need_c)
    out = []
    t0 = time.time()
    fn(quick, out)
    print(f"== {name}: done in {time.time() - t0:.1f} s", flush=True)
    if record:
        RESULTS.mkdir(exist_ok=True)
        suffix = "_quick" if quick else ""
        (RESULTS / f"{name}{suffix}.txt").write_text(header + "".join(out))


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("check", help="'list', 'all', 'clean' or a check name")
    ap.add_argument("--quick", action="store_true", help="reduced sample counts for rapid verification")
    ap.add_argument(
        "--record",
        action="store_true",
        help="write analysis/results/<check>.txt (or <check>_quick.txt with --quick)",
    )
    a = ap.parse_args()
    if a.check == "list":
        for k, (_, _, _, d, full, quick) in CHECKS.items():
            print(f"{k:10} {d}  [full: {full}; --quick: {quick}]")
    elif a.check == "clean":
        if BUILD.exists():
            BUILD.relative_to(HERE)
            shutil.rmtree(BUILD)
    elif a.check == "all":
        failed = []
        for k in CHECKS:
            if k == "integral" and not have_aesni_pclmul():
                print("== integral: skipped (needs an x86-64 CPU with AES-NI and PCLMULQDQ)", flush=True)
                continue
            try:
                run(k, a.quick, a.record)
            except (SystemExit, subprocess.CalledProcessError) as e:
                print(f"== {k}: FAILED ({e})", flush=True)
                failed.append(k)
        if failed:
            raise SystemExit(f"failed checks: {', '.join(failed)}")
    elif a.check in CHECKS:
        run(a.check, a.quick, a.record)
    else:
        raise SystemExit(f"unknown check {a.check!r}; see 'list'")


if __name__ == "__main__":
    main()
