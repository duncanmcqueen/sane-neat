# Neat NM-1000 scanner driver for Linux (SANE)

A SANE backend (`neat`) for the **Neat NM-1000 / Neat Receipts mobile scanner**
(USB `1f44:0001`), so it works with SimpleScan, `scanimage`, XSane and any other
SANE frontend. It needs no Neat software at runtime.

**ND-1000 (`1f44:0050`):** a separate, fully native SANE backend is available
below. The original `neat` backend remains NM-1000-only; `build/nd1000-probe`
can inspect the ND hardware. See [the investigation notes](re/README.md#nd-1000-investigation).

### ND-1000 SANE backend (native)

The `nd1000` backend drives the scanner directly through `src/nd1000.c`,
replaying register programs captured from Neat's Windows driver; **no vendor
software is needed at run time**. It decodes Color at 150/200/300/600 dpi on
the **front** and supports 300 dpi **back/duplex**. Gray is derived from Color.
The default is 300 dpi ADF Front. At 200 dpi the sensor-switch rows are
interpolated and some artifacts remain. Other back-side resolutions are not
yet decoded. The NM-1000 native driver below is independent.

```sh
make
sudo bash packaging/install-nd1000.sh
# Replug scanner; load one sheet and run:
scanimage -L
scanimage -d nd1000:usb:1f44:0050 --source 'ADF Front' --resolution 300 --format=png -o page.png
scanimage -d nd1000:usb:1f44:0050 --source 'ADF Front' --resolution 600 --format=png -o page-600.png
scanimage -d nd1000:usb:1f44:0050 --source 'ADF Duplex' --resolution 300 --format=png --batch='scan-%d.png' --batch-count=2
```

The installer also enables `saned.socket` (TCP 6566). It allows `127.0.0.1`,
Tailscale (`100.64.0.0/10`) and, by default, this host's primary LAN subnet;
set `ND_LAN_CIDR=YOUR_SUBNET/24` to override. On another Linux machine add this
host's LAN or Tailscale address to `/etc/sane.d/net.conf` and use
`scanimage -L`. The backend performs the page acquisition during `sane_start()`
and then serves the buffered image to the frontend.

To check the network path from the server itself, use the isolated client
configuration in `dev-sane/` (net backend pointed at localhost):

```sh
SANE_CONFIG_DIR="$PWD/dev-sane" scanimage -L
```

Limitations: the scanner's native gray mode is not available (the vendor DLL
crashes while capturing it), so `Gray` is produced by converting the colour
scan. The vendor's trailing-edge end-of-paper registers are not yet decoded:
the native scan is bounded to the requested height and then uses a content-
based trailing crop. `SNCmd 0x13` feed/eject is not decoded. The standalone
`nd1000-scan` tool shares the native full-pass decoder; like the SANE backend,
it only offers duplex at 300 dpi.

### NM-1000 features

- Colour or gray, 150 / 200 / 300 / 600 dpi, full 8.5" width
- Each sheet is scanned until its trailing edge passes the sensor, then ejected
- Uses the factory calibration stored in the scanner's own flash (read once,
  cached in `~/.cache/sane-neat/`)
- Exposed as a document feeder (`source = ADF`); an empty feeder reports
  "out of documents", which ends a SimpleScan batch

## Install (Fedora, including Atomic desktops)

Packages for current Fedora releases are published in the
[aeroevan/sane-neat](https://copr.fedorainfracloud.org/coprs/aeroevan/sane-neat/) COPR:

```sh
# Regular Fedora
sudo dnf copr enable aeroevan/sane-neat
sudo dnf install sane-backends-neat

# Atomic desktops (Silverblue, Kinoite, ...)
sudo curl -o /etc/yum.repos.d/sane-neat.repo \
  "https://copr.fedorainfracloud.org/coprs/aeroevan/sane-neat/repo/fedora-$(rpm -E %fedora)/aeroevan-sane-neat-fedora-$(rpm -E %fedora).repo"
sudo rpm-ostree install sane-backends-neat
```

Updates then arrive with the normal `dnf upgrade` / `rpm-ostree upgrade`.

To build the RPM yourself instead:

```sh
./packaging/build-rpm.sh            # builds dist/sane-backends-neat-*.rpm in a container
sudo rpm-ostree install ./dist/sane-backends-neat-[0-9]*.fc$(rpm -E %fedora).x86_64.rpm   # Atomic
# or: sudo dnf install ./dist/sane-backends-neat-[0-9]*.fc$(rpm -E %fedora).x86_64.rpm    # regular Fedora
```

On an Atomic desktop, reboot to switch to the new deployment (or try
`rpm-ostree apply-live`). Then plug the scanner in and open SimpleScan.

The package ships a udev rule (`70-neat-nm1000.rules`) that gives the logged-in
user access to the scanner.

## Using it

Put the sheet in **face down, against the left guide**, and push it in until the
rollers grab it. If a scan shows mirrored show-through, the sheet went in the
wrong way round.

```sh
scanimage -L
scanimage -d neat --mode Color --resolution 300 --format=png -o page.png
neat-scan info                       # serial number and paper sensor
neat-scan -r 300 -o page.pnm scan    # test tool that bypasses SANE
```

Debug output: `SANE_DEBUG_NEAT=3`. `NM1000_TRACE=file` logs all USB traffic.

## How it works

The scanner is built on a Genesys Logic **GL123**, a GL847-family ASIC. The
protocol was worked out by running Neat's own Windows driver DLL under a small
Linux PE loader (`re/pe-harness`) that forwards its `usbscan.sys` calls to
libusb and logs every transfer, then replaying those sequences natively:

- `src/nm1000.c`: device core (USB primitives, power-up, SPI-flash calibration
  reader, register-program interpreter, read loop with trailing-edge detection)
- `src/nm1000_tables.h`: per-mode register programs, generated by
  `re/tools/gen_tables.py` from the traces in `re/traces/` (regenerates
  identically)
- `src/sane-neat.c`: SANE backend
- `re/README.md`: notes on the reverse engineering and the harness

Native USB traffic matches the vendor driver's for all 8 modes, apart from how
many times timing-dependent polls repeat.

## Caveats

- 300 dpi colour is tested end to end on paper. The other seven modes produce
  the vendor's exact register and calibration sequences but have not yet been
  scanned on paper.
- Pages are buffered in memory (a 600 dpi colour letter page is about 100 MB).
- The first USB write after a power-up (`0x6e = 0x02`) can report an I/O error
  on some ports. This is harmless; the vendor driver sees it too.
- A bulk read with no scan data behind it locks the ASIC until it is unplugged,
  and a USB reset does not recover it. The driver never issues such a read.
  Don't remove the guard in `wait_for_data()`.

## License

GPL-2.0-or-later with the SANE exception (`GPL-2.0-or-later WITH SANE-exception`),
the same terms as most SANE backends. See `LICENSE` and `COPYING`.
