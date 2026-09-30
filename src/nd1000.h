// SPDX-License-Identifier: GPL-2.0-or-later WITH SANE-exception
/* Neat ND-1000 (USB 1f44:0050) duplex CIS scanner - device core interface.
 *
 * Replays register programs captured from Neat's Windows driver (see
 * re/tools/gen_tables_nd.py); no vendor code at run time. First cut: see
 * src/nd1000.c for what is verified versus still to decode.
 */
#ifndef ND1000_H
#define ND1000_H

#include <stddef.h>
#include <stdint.h>

#define ND1000_VENDOR 0x1f44
#define ND1000_PRODUCT 0x0050

enum nd1000_status {
    ND1000_OK = 0,
    ND1000_EOF = 1,      /* all sides of the page read */
    ND1000_SIDE_DONE = 2, /* current side ended; more sides follow */
    ND1000_ERR_IO = -1,
    ND1000_ERR_NODEV = -2,
    ND1000_ERR_NOPAPER = -3,
    ND1000_ERR_INVAL = -4,
    ND1000_ERR_NOMEM = -5,
    ND1000_ERR_BUSY = -6,
    ND1000_ERR_CANCELLED = -7,
};

struct nd1000;

/* Defined in the generated nd1000_tables.h. */
struct nd1000_mode;

struct nd1000_scan_info {
    int dpi;
    int color;
    int pixels;
    int bytes_per_line;
    int max_lines;
};

typedef void (*nd1000_log_fn)(int level, const char *msg);
void nd1000_set_log(nd1000_log_fn fn);

int nd1000_open(struct nd1000 **dev, int bus, int address);
void nd1000_close(struct nd1000 *dev);
const char *nd1000_serial(struct nd1000 *dev);
const char *nd1000_strerror(int status);

/* 1 if a sheet is at the input sensor, 0 if not, <0 on error. */
int nd1000_paper_present(struct nd1000 *dev);

/* Supported resolutions (dpi), terminated by 0. */
const int *nd1000_resolutions(void);

/* ND-1000 image path (validated byte-exact against the vendor output at 150 dpi
 * colour; see re/README.md). The raw image FIFO packs each line as 6 sectors of
 * 666 little-endian uint16 samples (15 sync + 651 data); the delivered page uses
 * sectors 3-5 as R/G/B and each sample's two bytes are two adjacent output
 * pixels. `ND1000_WARMUP_LINES` raw lines are discarded before the page starts. */
#define ND1000_RAW_BPL_150_COLOR 7992
#define ND1000_WARMUP_LINES 70

/* Unpack one raw 150 dpi colour line (ND1000_RAW_BPL_150_COLOR bytes) into
 * `pixels` RGB pixels. `pixels` must be 1272. Returns 0. */
int nd1000_unpack_150_color(const uint8_t *raw, uint8_t *out, int pixels);

/* Decode a whole side from a concatenated raw image-FIFO record stream (the
 * bytes as delivered by the device, 6 sectors per record). `dpi`/`side`
 * (0 front, 1 back) select the recovered per-mode packing; `out` receives
 * `width * height * 3` interleaved RGB bytes. Returns 0, or <0 unsupported. */
int nd1000_decode_page(int dpi, int side, const uint8_t *raw, size_t nbytes,
                       uint8_t *out, int width, int height);

/* Align decoded rows to the page. The vendor DLL's returned raster still has
 * a periodic horizontal shift at 200/300/600 dpi. Returns ND1000_OK or an
 * ND1000_ERR_* code. 150 dpi needs no correction. */
int nd1000_realign_page(int dpi, int side, uint8_t *rgb, int width, int height);

/* Number of output rows decodable from `nbytes` of raw record stream for
 * (dpi, side); <0 if unsupported. */
int nd1000_decode_height(int dpi, int side, size_t nbytes);

/* Drain the whole image FIFO for one physical pass into a malloc'd buffer
 * (all sides are carried in the same record stream). Caller frees *raw.
 * Returns ND1000_ERR_CANCELLED if the optional cancel callback (set with
 * nd1000_set_cancel) reports cancellation while draining. */
int nd1000_read_all(struct nd1000 *dev, uint8_t **raw, size_t *len);

/* Install a callback polled between drain chunks; a nonzero return marks the
 * drain cancelled. The drain still runs to its bound so the sheet is ejected,
 * and nd1000_read_all then returns ND1000_ERR_CANCELLED. Pass NULL to clear. */
void nd1000_set_cancel(struct nd1000 *dev, int (*cb)(void *ref), void *ref);

int nd1000_start(struct nd1000 *dev, int dpi, int max_height_mm, struct nd1000_scan_info *info);

/* Enable/disable duplex (front+back) for subsequent scans. */
void nd1000_set_duplex(struct nd1000 *dev, int enabled);

/* Current side index: 0 front, 1 back. */
int nd1000_side(struct nd1000 *dev);

/* Number of leading lines of an image, dropping trailing all-0x00/0xff blank
 * rows the scan engine pads to the programmed height. */
int nd1000_trim_trailing_blank(const uint8_t *buf, int bpl, int lines);

/* Read up to max_lines complete lines (RGB interleaved or gray) into buf.
 * Returns ND1000_OK with *lines set, ND1000_SIDE_DONE when the current side
 * ended (more sides remain), or ND1000_EOF when the page is complete. */
int nd1000_read(struct nd1000 *dev, uint8_t *buf, int max_lines, int *lines);

/* Finish or abort a scan. */
int nd1000_finish(struct nd1000 *dev);

/* Move the paper by replaying the captured SNCmd(0x13) feed program `steps`
 * times (1..64). The vendor's step argument is ignored; each replay runs two
 * fixed microstep moves in the feed/grab (inward) direction. */
int nd1000_feed(struct nd1000 *dev, int steps);

#endif
