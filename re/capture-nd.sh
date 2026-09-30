#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-or-later WITH SANE-exception
# Capture ND-1000 vendor-driver traces for the mode matrix.
#
#   re/capture-nd.sh /path/to/neatadfscanner_x64.dll [outdir]
#
# Without NEAT_WITH_PAPER this captures only the register-programming phases
# (open, set-params, load-calib, lamp, stop) with no paper loaded. The DLL's
# own paper check refuses to run the scan kickoff on an empty feeder, so the
# mode-specific `start` phase needs a sheet. Set NEAT_WITH_PAPER=1 and load a
# sheet before each mode to capture the full scan.
set -euo pipefail

dll=${1:?usage: capture-nd.sh /path/to/neatadfscanner_x64.dll [outdir]}
out=${2:-re/traces/nd}
mkdir -p "$out"

for res in 150 200 300 600; do
    for bpp in 24 8; do
        tag="${res}_${bpp}"
        if [[ -n ${NEAT_WITH_PAPER:-} ]]; then
            echo "Load a sheet for ${res} dpi / ${bpp} bpp, then press Enter..."
            read -r
            NEAT_USB_PID=0050 \
            NEAT_TRACE="$out/scan_${tag}.log" \
                re/pe-harness/neatcap "$dll" duplex "$res" "$bpp" \
                "$out/front_${tag}.pnm" "$out/back_${tag}.pnm" >/dev/null 2>&1 || true
            echo "  captured $out/scan_${tag}.log"
        else
            NEAT_USB_PID=0050 NEAT_NOPAPER=1 \
            NEAT_TRACE="$out/prog_${tag}.log" \
                re/pe-harness/neatcap "$dll" program "$res" "$bpp" >/dev/null 2>&1 || true
            echo "captured $out/prog_${tag}.log"
        fi
    done
done
