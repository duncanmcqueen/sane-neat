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
`1f44:0001`. The ND bridge installer installs this rule automatically;
`make install` only installs the original NM backend.

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
both sides; `src/sane-nd1000.c` serves them as two SANE pages and exposes
`ADF Front` / `ADF Back` / `ADF Duplex`. The NM-style eject (`0x13`) expects
additional ND-specific arguments, so the harness does **not** attempt ND
ejection. No native ND register tables have been validated yet; the bridge
still needs Neat's DLL at runtime.

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
