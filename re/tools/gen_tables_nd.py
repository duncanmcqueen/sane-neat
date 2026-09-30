#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later WITH SANE-exception
"""Generate src/nd1000_tables.h from neatcap traces of the ND-1000 driver.

Prototype: mirrors re/tools/gen_tables.py, but the ND-1000 is a GL847-family
duplex scanner (front/back CIS). Per-mode `start` capture needs a sheet, so a
scan directory with scan_<res>_<bpp>.log is required alongside the no-paper
prog_<res>_<bpp>.log files produced by re/capture-nd.sh.

usage: gen_tables_nd.py PROGDIR SCANDIR > src/nd1000_tables.h
  PROGDIR: prog_<res>_<bpp>.log   (open, set-params, load-calib)
  SCANDIR: scan_<res>_<bpp>.log   (lamp, start, stop)
"""
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
from tracephase import parse  # noqa: E402

OP_END, OP_W, OP_SLEEP, OP_8C, OP_BULK, OP_AFECAL, OP_SHADING, OP_LINCNT, OP_WAITMOTOR, OP_CTRLW, OP_BULKIN, OP_CTRLR = range(12)

MODES = [(res, bpp) for res in (150, 200, 300, 600) for bpp in (24, 8)]


def phase(phases, name, nth=0):
    hits = [p for p in phases if p['name'] == name]
    if not hits:
        raise SystemExit('phase %r not found' % name)
    return hits[nth]['ops']


def maybe(path, name):
    """Return a phase's ops, or [] with a warning if the trace/phase is absent.
    Partial captures (no paper, vendor DLL aborted) are common while the mode
    matrix is being filled in."""
    if not os.path.exists(path):
        sys.stderr.write('warning: %s missing; empty %s program\n' % (path, name))
        return []
    try:
        return phase(parse(path), name)
    except SystemExit:
        sys.stderr.write('warning: %s has no %r phase; empty program\n' % (path, name))
        return []


def is_flash_hdr(op):
    return op[0] == 'HDR' and (op[2] >> 24) == 0x03


def encode(ops, calib=False):
    out = []
    ops = list(ops)
    afecal_idx = None
    if calib:
        for i, op in enumerate(ops):
            if op[0] == 'HDR' and op[1] == 1 and (op[2] >> 24) == 0x10 and op[3] > 4096:
                j = i - 1
                while ops[j][0] != 'W':
                    j -= 1
                afecal_idx = j
                break
    skip_next_bo = False
    shading_ch = 0
    i = 0
    while i < len(ops):
        op = ops[i]
        kind = op[0]
        if kind in ('CI', 'BI'):
            if (kind == 'CI' and op[1] == '008e' and 2 <= op[3] <= 9
                    and (int(op[2], 16) & 0xff) == 0x22):
                # Small register status poll using the 0x8e buffer-read protocol
                # (index low byte 0x22). The vendor DLL interleaves these with
                # the command writes as a write-then-poll handshake (e.g. poll
                # status 0x40 around the motor/command register 0x02). Dropping
                # them made the native replay fire commands without waiting and
                # the paper fed ~1.8x fast (image squashed). Replay them.
                # `op[3]` is the transfer length (values + one 0x55 status
                # byte); read_regs() adds the status byte itself, so pass
                # op[3] - 1. Single-byte 0x0c direct reads (no status byte) and
                # the 64-byte config readbacks are not replayed.
                index = int(op[2], 16)
                out.append([OP_CTRLR, index >> 8, op[3] - 1])
            # Other CI (EEPROM/config readbacks) and BI reads are not replayed.
        elif kind == 'W':
            if i == afecal_idx:
                out.append([OP_AFECAL])
            else:
                # Unlike the NM-1000, the ND driver writes 0 to LINCNT first,
                # then a much larger mode-specific hardware limit. Replacing
                # both with the frontend's page height suppresses the paper
                # edge event. Preserve both vendor writes verbatim.
                out.append([OP_W, len(op[1])] + [b for p in op[1] for b in p])
        elif kind == 'SLEEP':
            ms = op[1]
            out.append([OP_SLEEP, ms & 0xff, ms >> 8])
        elif kind == 'CO' and op[2] == '008c':
            out.append([OP_8C, int(op[3], 16), int(op[4], 16)])
        elif kind == 'CO' and op[2] == '008b':
            # ND calibration/EEPROM address write: CO 04 008b <index> <len> <data>.
            # The native core must implement this; the matching data read is
            # CI 04 008a, which is calibration data and replayed natively too.
            req = int(op[1], 16)
            value = int(op[2], 16)
            index = int(op[3], 16)
            data = bytes.fromhex(op[4]) if op[4] else b''
            out.append([OP_CTRLW, req, value & 0xff, value >> 8, index & 0xff, index >> 8,
                        len(data)] + list(data))
        elif kind == 'HDR':
            if is_flash_hdr(op):
                skip_next_bo = True
            elif op[1] == 1:
                nxt = ops[i + 1]
                assert nxt[0] == 'BO' and nxt[1] == op[3], (op, nxt)
                data = bytes.fromhex(nxt[2])
                addr, ln = op[2], op[3]
                if calib and ln > 4096:
                    pad = int.from_bytes(data[4:8], 'little')
                    hdr_first = 1 if any(data[0:4]) else 0
                    out.append([OP_SHADING, shading_ch] + list(addr.to_bytes(4, 'little')) +
                               list(ln.to_bytes(4, 'little')) + list(pad.to_bytes(4, 'little')) +
                               [hdr_first])
                    shading_ch += 1
                else:
                    out.append([OP_BULK] + list(addr.to_bytes(4, 'little')) +
                               list(ln.to_bytes(2, 'little')) + list(data))
                i += 1
            else:
                # Bulk-in read (e.g. gamma readback at 0x01000000). The native
                # core performs the transfer; the returned bytes are not replayed.
                out.append([OP_BULKIN] + list(op[2].to_bytes(4, 'little')) +
                           list(op[3].to_bytes(4, 'little')))
                if i + 1 < len(ops) and ops[i + 1][0] == 'BI':
                    i += 1
        elif kind == 'BO':
            if not skip_next_bo:
                raise SystemExit('bulk out without header: %r' % (op,))
            skip_next_bo = False
        elif kind == 'BI':
            pass  # consumed with its bulk-in header
        else:
            raise SystemExit('unhandled op %r' % (op,))
        i += 1
    out.append([OP_END])
    return [b for o in out for b in o]


def c_array(name, prog):
    lines = ['static const uint8_t %s[%d] = {' % (name, len(prog))]
    for k in range(0, len(prog), 16):
        lines.append('    ' + ', '.join('0x%02x' % b for b in prog[k:k + 16]) + ',')
    lines.append('};')
    return '\n'.join(lines)


def main():
    progdir, scandir = sys.argv[1:3]
    warm = parse(os.path.join(progdir, 'prog_150_24.log'))
    print('// SPDX-License-Identifier: GPL-2.0-or-later WITH SANE-exception')
    print('/* Generated by re/tools/gen_tables_nd.py from ND-1000 vendor traces.')
    print(' * Prototype: incomplete modes emit empty programs and a warning. */')
    print('#ifndef ND1000_TABLES_H\n#define ND1000_TABLES_H\n\n#include <stdint.h>\n')
    print('enum { OP_END, OP_W, OP_SLEEP, OP_8C, OP_BULK, OP_AFECAL, OP_SHADING, OP_LINCNT, OP_WAITMOTOR, OP_CTRLW, OP_BULKIN, OP_CTRLR };\n')
    print(c_array('prog_common_init', encode(phase(warm, 'open'))))
    scan150 = os.path.join(scandir, 'scan_150_24.log')
    print(c_array('prog_lamp_on', encode(maybe(scan150, 'lamp'))))
    print(c_array('prog_stop', encode(maybe(scan150, 'stop'))))
    # Feed/grab: a single SNCmd(0x13) call captured via neatcap's raw path
    # (NEAT_ND_RAW=1). The program is fixed; the p6 step argument does not
    # change the USB stream (p6=300 and p6=1000 captures were identical), and
    # the 510-byte bulk-out is the motor microstep profile.
    print(c_array('prog_feed', encode(maybe(os.path.join(progdir, 'feed.log'), 'raw'))))
    print()

    entries = []
    for res, bpp in MODES:
        tag = '%d_%s' % (res, 'color' if bpp == 24 else 'gray')
        prog = os.path.join(progdir, 'prog_%d_%d.log' % (res, bpp))
        scan = os.path.join(scandir, 'scan_%d_%d.log' % (res, bpp))
        print(c_array('prog_setparams_' + tag, encode(maybe(prog, 'set-params'))))
        # First native cut: replay the captured calibration/shading uploads
        # inline rather than via OP_SHADING, so no native flash reader is
        # needed yet. Switch to calib=True once the 0x8b/0x8a reader exists.
        print(c_array('prog_calib_' + tag, encode(maybe(prog, 'load-calib'))))
        print(c_array('prog_start_' + tag, encode(maybe(scan, 'start'))))
        print()
        entries.append((res, bpp, tag))

    print('struct nd1000_mode {')
    print('    int dpi;\n    int color;\n    int flash_region;\n    int pixels;')
    print('    const uint8_t *setparams, *calib, *start;\n};\n')
    print('static const struct nd1000_mode nd1000_modes[] = {')
    for res, bpp, tag in entries:
        pixels = res * 85 // 10 & ~3
        print('    {%d, %d, %d, %d, prog_setparams_%s, prog_calib_%s, prog_start_%s},' %
              (res, bpp == 24, 0, pixels, tag, tag, tag))
    print('};\n')
    print('#endif')


if __name__ == '__main__':
    main()
