# Reverse-engineering notes

These tools are only needed to extend or re-derive the driver. The driver itself
contains no vendor code.

## Vendor driver

The NM-1000 trace was made with Neat's mobile Windows driver:

    https://s3.amazonaws.com/scanner-drivers/Windows/NeatMobile/x64/Scanner.Install64.Neat.Mobile.MSI.msi
    sha256 cb006d10beb41cc20d14eb0b35cbdb866fb0ddba44335644bf42d66ff9cba794

`7z x` the MSI to get `neatmobilescanner_x64.dll`. It has a single export,
`int SNCmd(cmd, uint *params, void *buf, float *f, int p5, uint p6)`:

The ND-1000 has its **own** Windows package at
`https://s3.amazonaws.com/scanner-drivers/Windows/NeatDesk/x64/Scanner.Install64.Neat.ADF.MSI.msi`.
Its INF explicitly matches USB `1f44:0050`, and the package contains
`neatadfscanner_x64.dll`, which also exports `SNCmd`. Its commands and register
tables have **not** been checked against the NM-1000 traces. Do not run the
NM-1000 scan core against the ND-1000 just by changing the product ID.

### ND-1000 investigation

Build the discovery tool and tracing harness:

    make
    make -C re/pe-harness
    ./build/nd1000-probe

The default probe only enumerates USB descriptors. The optional
`./build/nd1000-probe --read-register-41` sends **one** NM-style register read
(no writes or motor actions); it needs USB access. A `0x55` status indicates
that this read format is recognized, but does not validate NM register programs.
Fix the device's udev ACL first; do not run scanning software as root.
The USB node usually belongs to root without an ACL. For a temporary test, use
the bus and device numbers reported by `nd1000-probe` (they change when
replugging); for example, if it reports bus 003 address 060:

    sudo setfacl -m "u:$(id -u):rw" /dev/bus/usb/003/060
    ./build/nd1000-probe --read-register-41

For persistent access, install
`udev/64-neat-nd1000.rules` into `/etc/udev/rules.d/`, reload udev rules and
replug the scanner. The NM-1000's `udev/70-neat-nm1000.rules` only covers
`1f44:0001`. The native ND installer
(`packaging/install-nd1000.sh`) installs this rule automatically; `make install`
only installs the original NM backend.

    sudo install -m 644 udev/64-neat-nd1000.rules /etc/udev/rules.d/
    sudo udevadm control --reload-rules
    # unplug and replug the scanner, then verify with getfacl on its new USB path

For a vendor-driver trace, extract the ND MSI with `7z x` and run the harness
with the ND DLL and `NEAT_USB_PID=0050`. The harness forwards USB requests from
the vendor DLL to real hardware, so start with `status` and examine the trace
before attempting scan, feed, or calibration. It is not needed for normal SANE
operation and does not install a Windows driver:

    NEAT_USB_PID=0050 NEAT_TRACE=nd-status.log \
      re/pe-harness/neatcap /path/to/neatadfscanner_x64.dll status

For a duplex capture, pass front and back output paths:

    NEAT_USB_PID=0050 re/pe-harness/neatcap /path/to/neatadfscanner_x64.dll \
      duplex 150 24 front.pnm back.pnm

The harness selects the USB device by `NEAT_USB_PID` and passes the real
attached device's VID/PID and, for the ND-1000, `bcdDevice` to the DLL; the
NM-1000 keeps the descriptor constant its driver expects. Some DLL imports may
need additional stubs before the ND driver can run. Keep the DLL and captured
traces outside this GPL repository. Once the ND trace is known, derive separate
initialization, calibration, motor, duplex, and scan programs; the existing
`nm1000_tables.h` is specific to the NM-1000.

ND findings: `SNCmd(0x16)` returns `1` with a sheet loaded and `0xe107`
with an empty feeder. `SNCmd(0x9)` dereferences the fourth argument, unlike
the NM DLL. The ND TWAIN source uses scan method `0x80` for duplex,
`0x800` for simplex/ADF, and `0x08` for flatbed; method `0x08` detected the
sheet but never moved it and timed out with `0xe11c`. With `0x80`, the device
images **both sides in one pass**: reads return full lines for the front until
status `0x1001`, then full lines for the back until `0xe10d`. At 150 dpi each
side is `1272x1600` RGB. The harness `duplex RES BPP FRONT BACK` action captures
both sides; `src/sane-nd1000.c` serves them as two SANE pages through the
native core and exposes `ADF Front` / `ADF Back` / `ADF Duplex`. The NM-style
eject (`0x13`) expects additional ND-specific arguments, so the harness does
**not** attempt ND ejection.

Native core validation (`src/nd1000.c` vs the vendor traces): replaying the
captured programs reproduces the vendor programming at NM-1000 parity —
set-params and lamp match exactly, load-calib 0.97 and start 0.98 (differences
are timing-dependent motor/line-count registers only). The ND motor wait polls
register 0x41, not the NM-1000's 0x40.

Read/duplex protocol: each `SNCmd(6)` call issues up to two bulk reads from the
image FIFO (259740 + 251748 bytes at 150 dpi). A **short** bulk read marks the
end of a side — the front-end call returned 215784 bytes and reported `0x1001`;
the back end reported `0xe10d`. Register 0x41 bit 0x40 tracks the side
(`0x8d` front, `0xcd` back), and the driver caches the front image in
`TopImage.raw` between sides, so one native start covers both sides of a sheet.

Trailing-edge (end-of-paper) detection: deeper dive **still unresolved**, with
the mechanisms now identified. The generator previously replaced both vendor
LINCNT writes with the frontend's page height; the vendor actually writes `0`
first and then a large mode-specific hardware limit (150 dpi `0x69ec` = 27116,
200 `0x8d58`, 300 `0xd3d8`, 600 `0xd4f0`). `gen_tables_nd.py` now preserves both
verbatim. With that corrected, a 150 dpi scan still delivers the full read bound
(1647 lines at 279 mm) and does not latch a paper event; over-provisioning to
330 mm latches reg 0x40 bit 6 only at ~1948 lines with `0x4b-0x4d = 0x15bb`,
far beyond the sheet, so it is not a usable page-length signal. The vendor's
~1600-line crop therefore depends on driver-side timing/setup not reproduced by
replaying the captured register programs alone. The native core logs the
candidate registers (reg 0x40 bit 6, `0x4b-0x4d`, `0x92-0x93`) without changing
the scan length. Practical alternative: crop from content.

Gray captures remain blocked, now root-caused. `SNCmd(0x4)` (load-calib)
segfaults in the vendor DLL at `0x180016e4e` dereferencing the gray-only
`LineDark` pointer at `ctx+0x2d8`, which only becomes NULL on some paths. At
300 dpi it is populated by an earlier `Line`/`OpticalBlack` adapter config, so
300 gray works; at 150/200/600 the same pointer is NULL. Reproducing that
requires the `.ds` TWAIN adapter-chaining engine (the harness only replays
`SNCmd`), so native gray is not reachable this way. The SANE backend offers Gray
by converting the colour scan instead.

Native image colour is **solved** for 150 dpi colour (validated byte-exact).
The raw image FIFO is the image but must be repacked. Full FIFO
(`NEAT_BULK_DIR`) on a 150 dpi colour scan = 13,850,136 bytes; each SNCmd(6)
frame is **64 lines x 7992 bytes** (511488 B), each 7992-byte line is **6
sectors of 666 little-endian uint16 samples**, each sector **15 sync + 651 data
samples**. The six sectors are two 3-sector CIS groups; the front page uses
**group B (sectors 3-5) = R,G,B**, and **output row r uses raw block r+70**
(blocks 0-69 warm-up).

Each 16-bit sample carries **two adjacent output pixels, one per byte**. With
`k = j/3`, phase `j%3`, `Hi(v)=v>>8`, `Lo(v)=v&0xFF`:

| sample | byte | column | byte | column |
|---|---|---|---|---|
| `3k+2` | `Hi` | `2k+1`   | `Lo` | `2k+861` |
| `3k+1` | `Lo` | `2k`     | `Hi` | `2k+431` |
| `3k+0` | `Lo` | `2k+430` | `Hi` | `2k+860` |

(left `k=0..214`; middle odd `k=0..214`, middle even `k>=1`; right odd
`k=0..205`, right even `k>=1`). Columns **x=430 and x=860** have no raw source
and equal the mean of their neighbours. The DLL's `0x180014d50` is a modulo-255
carry normaliser (magic `0x80808081`) that redistributes the sub-LSB remainder;
`0x18001abe0` is `memmove`; `0x180011d70` is a 252->256-sample stride repacker
used only on the 600 dpi branch; `ThreeChannelShift=590/8` is a calibration
entry count, not a pixel shift. The per-pixel dark/gain stages (`0x180007898`,
`0x180007f60`) and the `/255` quantizer (`0x180015170`) are **not** applied on
this path (no gamma either) — the delivered byte is literally `Hi`/`Lo`.

Implemented in `src/nd1000.c` as `nd1000_unpack_150_color()` with a raw-framed
read path (`nd1000_read_raw()`), used for 150 dpi colour. Regenerated offline
from the FIFO dump it reproduces `/tmp/opencode/ref-front.pnm` **byte-for-byte
(6,296,400 / 6,296,400, max error 0)**; test harness
`/tmp/opencode/unpack_test.c`.

**Generic transform (from DLL disassembly, `re/.../D_findings.md`).** The 150
formula is a special case of one assembler in `0x18001563d`:
- 150 dpi: 6 sectors x (15 sync + 651 data), output 1272 wide, warm-up 70.
- 200 dpi: 6 sectors x (**21 sync + 861 data** = 42 B sync + 1722 B), output
  1700 wide. Decode window = **first 1718 bytes of the 1722-byte data** (859 of
  861 samples; last 2 unused). Per channel, per row `r`: `t = r%98`,
  `rec = 92 + r - r//98`; output column `x` = `data[(3x + b(t)) mod 1718]`, a
  stride-3 circular read. `b` drifts **-12 B/row = 4 columns/row** and resets
  every 98 rows; the `x < 4t`
  columns come from the previous record at `b-42`. Both 3-sector groups image
  the **same front page**, alternating in **48-row blocks**: group B (sectors
  3-5) for `t=0..47`, group A (sectors 0-2, horizontally mirrored) for
  `t=49..96`; rows `t=48,97` are sensor-switch rows. Seams at 573/1146 (B) and
  551/1124 (A) are neighbour means; the page-edge margin column has no raw
  source. Measured: **150 exact 1.000000**, **200 0.999100** on non-transition
  rows (residual = margin column + the 44 switch rows).

Port status: the byte decoder is ported to C (`nd1000_decode_page()` and
`nd_packs` in `src/nd1000.c`) for **150/200/300/600 front and 300 back**.
`nd1000_read_all()` captures a pass, then the SANE backend decodes the requested
side(s); Gray is derived from decoded colour. 150/200/600 **back remain
unsupported** by the C decoder. Offline comparison against the DLL's *intermediate*
raster: 150F 1.000000, 300F 0.999608, 300B 0.999238, 600F 0.999626,
200F 0.989121. At 200 the residual includes 44 sensor-switch rows for which
the decoder has no samples.

**Final row alignment (previously missing).** The vendor DLL's direct `SNCmd(6)`
buffer is not a finished, aligned page. A 300 dpi capture of the *same sheet*
through the vendor harness and native backend produced the same diagonal,
shredded text, even though both raw streams have identical sector boundaries.
The apparent 29-vs-30 leading-zero discrepancy is a phase of the sensor data,
not a dropped sample. Row-wise horizontal displacement remains in *both*
rasters. Undo it after byte decoding with a cyclic pixel shift:

| dpi / side | horizontal shift per row (positive = right) |
|---|---|
| 150 front | none |
| 200 front | `-4 * (row % 98)`; interpolate the missing rows `row%98 = 48,97` |
| 300 front | `+4 * (row % 32)` |
| 300 back | `+4 * (row % 636)` |
| 600 front | `+12 * (row % 16)` |

At 300 front this reduces adjacent-row mean absolute difference from 9.02 to
6.63 on the same-sheet vendor image and restores legible text in *both* vendor
and native previews. 600 front and 300 back likewise become legible. 200 front
remains visibly imperfect at group switches, even after interpolation.
`nd1000_realign_page()` implements this as a separate post-decode stage and is
called before cropping/Gray conversion. An offline C-vs-numpy comparison is
byte-exact for every supported row-alignment variant.

**Feature parity with upstream `aeroevan/sane-neat` (`neat` backend).** The ND
backend advertises Color/Gray and 150/200/300/600 dpi; Gray is colour-derived.
It reports `SANE_STATUS_NO_DOCS` on an empty feeder and provides a udev rule and
standalone tool. Remaining: validated back-side decoding at 150/200/600,
*reasonable* 200 dpi switch-row reconstruction (the C path interpolates the
switch rows, but no raw sample source for them is decoded), exact
trailing-edge detection (currently bounded read plus a content-crop heuristic),
and cancellation while a blocking scan is underway. Geometry options
(`tl-x/tl-y/br-x/br-y` in mm) and window cropping are implemented; the default
resolution is now 300 dpi. `nd1000-scan` shares the whole-pass decoder and
rejects unsupported back-side modes before feeding.

The harness/bridge path (running the vendor DLL) remains the fallback.

**Feed-rate bug (fixed).** The first native scan produced the correct page but
vertically squashed to 939 lines instead of ~1650. Cause: the captured program
tables replayed only the register *writes*; `gen_tables_nd.py` deliberately
dropped every `CI` (register read). The vendor DLL's set-params/start phases are
**writes interleaved with small status reads** (`CI 008e 4022 3`, i.e. poll
register 0x40) — a write-then-poll handshake on the command register 0x02.
Firing the `0x02` commands without waiting for the polls made the device miss
them and feed the paper ~1.8x fast, so the whole page was compressed into ~57%
of the lines. Fix: `OP_CTRLR` (added to the generator and `run_prog`) replays the
small (`len <= 8`) `CI 008e` reads at their captured positions; the 64-byte
config readbacks are still skipped (they time out if replayed at open). With the
handshake replayed, a 150 dpi ADF-front scan now comes out full height
(`1272x1614`). See `re/tools/gen_tables_nd.py` and `src/nd1000.c:OP_CTRLR`.

**Trailing over-scan (cropped from content).** The engine runs to the
programmed height, so after the sheet leaves the CIS the tail rows are dark
(background). `nd1000_trim_trailing_blank()` now also drops trailing rows with
no pixel brighter than `ND1000_PAPER_MAX` (128), which removes the dark band
while leaving a dark-but-real page intact (if the whole image is dark it is left
unchanged). This is a heuristic; the vendor's hardware page-end signal is still
not reproduced.

| cmd  | meaning                                          |
|------|--------------------------------------------------|
| 1/8  | open / close                                     |
| 2    | set parameters (0x840-byte block, see neatcap.c) |
| 3    | calibrate with the calibration sheet             |
| 4    | load calibration (flash, cached to AppData)      |
| 5    | start scan                                       |
| 6    | read `p6` bytes into `buf`                       |
| 7    | stop                                             |
| 9    | lamp on/off (`p5`)                               |
| 0x10 | buttons                                          |
| 0x13 | feed `p6` motor steps                            |
| 0x16 | paper present? (NM: 0 = yes; ND: 1 = yes, 0xe107 = empty)  |

## pe-harness

`neatcap` loads the x64 DLL into a Linux process, stubs about 95 kernel32/user32
imports, maps `\\.\USBSCAN0` + `DeviceIoControl`/`ReadFile`/`WriteFile` onto
libusb, and logs every transfer:

    make -C re/pe-harness
    NEAT_TRACE=trace.log re/pe-harness/neatcap neatmobilescanner_x64.dll scan 300 24 out.ppm

`NEAT_NOPAPER=1` skips the paper check, which is enough to capture register
programming. It creates a `winroot/` sandbox for the files the DLL writes.

## Protocol summary

- Register write: `40 04|0c 0083 0000`, data = (reg, val) pairs.
- Register read: `c0 04 008e (0x22 | reg<<8)`, returns n values + `0x55`.
- Bulk: `40 04 0082 {0=in,1=out}` with addr32/len32 LE, then EP 0x81 / 0x02.
  - `0x10000000` image FIFO (colour lines arrive as R, G, B planes)
  - `0x10014000` etc. shading tables, `0x01000000` gamma, `0x1000c000` motor
  - `0x03000000` SPI flash controller; set GPIO `a7=01 a6=1d` first and
    `a7=00 a6=1c` afterwards
- AFE: reg 0x51 = address, 0x3a/0x3b = data.
- Flash: calibration regions 0x00xxxx (600 colour), 0x01xxxx (300 colour),
  0x02xxxx (600 gray), 0x03xxxx (300 gray). 150/200 dpi reuse the 300 tables.
  Each table is `[AFE offset, AFE gain, (dark, gain) per pixel ...]`.
- Paper: write `0a=20`, then reg 0x40 bit 6 = no paper. After the trailing edge,
  the remaining lines = (regs 0x92:0x93 + regs 0x4b:0x4d) / 3 in colour
  (/1 in gray).
- Power-up (reg 0x41 bit 7 clear): see `cold_init()` in `src/nm1000.c`.

## Regenerating tables

    mkdir /tmp/t && cp re/traces/*.xz /tmp/t && xz -d /tmp/t/*.xz
    re/tools/gen_tables.py /tmp/t /tmp/t/warm_open.log /tmp/t/scan_300_color.log > src/nm1000_tables.h
