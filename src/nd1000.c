// SPDX-License-Identifier: GPL-2.0-or-later WITH SANE-exception
/* Neat ND-1000 (USB 1f44:0050) device core. GL847-family duplex CIS scanner.
 *
 * This is the native counterpart to the ND-1000 SANE bridge: it replays the
 * register programs captured from Neat's own Windows driver (see
 * re/tools/gen_tables_nd.py and re/README.md) and talks to the device with
 * libusb, so no vendor software is needed at run time.
 *
 * Status: the SANE backend (src/sane-nd1000.c) is wired to this core. The
 * captured programming phases are faithful to the vendor traces (diff with
 * ND1000_TRACE against re/pe-harness NEAT_TRACE). Calibration is replayed
 * inline by nd1000_tables.h rather than read from the device's 0x8b/0x8a
 * EEPROM path. Image decoding is recovered for 150/200/300/600 front and 300
 * back (see nd1000_decode_page); trailing-edge detection is approximated by a
 * bounded drain plus a content crop.
 */
#define _GNU_SOURCE
#include "nd1000.h"

#include <errno.h>
#include <libusb-1.0/libusb.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "nd1000_tables.h"

#define EP_IN 0x81
#define EP_OUT 0x02
#define CTRL_TIMEOUT 5000
#define BULK_TIMEOUT 30000
#define BULK_MAX 0xeff0

#define REQ_REGISTER 0x0c
#define REQ_BUFFER 0x04
#define VAL_BUFFER 0x82
#define VAL_SET_REGISTER 0x83
#define VAL_TIMING 0x8c
#define VAL_GET_REGISTER 0x8e

#define SCAN_FIFO 0x10000000u
#define ND_READ_BYTES 262144 /* vendor reads ~250 KiB per bulk transfer */

/* A trailing row with no byte at least this bright is over-scan (the sensor
 * seeing the dark background after the sheet has left), not page content. */
#define ND1000_PAPER_MAX 128

struct nd1000 {
    libusb_context *ctx;
    libusb_device_handle *h;
    char serial[32];

    const struct nd1000_mode *mode;
    int scanning;
    int bpl;
    int lines_max;
    int lines_done;   /* lines delivered for the current side */
    int chunk_lines;
    uint8_t *chunk;
    int raw_bpl;      /* bytes per raw FIFO line (0 = raw line == output line) */
    int raw_reclen;   /* per-dpi raw record size, for bounding a drain */
    int warmup_left;  /* raw lines still to discard before the page starts */
    uint8_t *rawbuf;
    size_t rawfill;
    FILE *bulk;       /* ND1000_BULK_DIR raw FIFO dump for the current side */
    int data_seen;
    int side;         /* 0 front, 1 back */
    int sides;        /* 1 simplex, 2 duplex */
    int edge_seen;    /* diagnostic: paper sensor event latched */
    int (*cancelled)(void *ref); /* polled while draining; nonzero aborts */
    void *cancel_ref;
};

static nd1000_log_fn log_fn;

/* ND1000_TRACE=file logs all USB traffic in the neatcap trace format so the
 * native programming can be diffed against the vendor traces. */
static FILE *trace_fp;
static int trace_init_done;

static FILE *trace_file(void)
{
    if (!trace_init_done) {
        const char *p = getenv("ND1000_TRACE");
        trace_init_done = 1;
        if (p && *p)
            trace_fp = fopen(p, "w");
    }
    return trace_fp;
}

static void trace_xfer(const char *kind, const char *head, const uint8_t *data, int len, int max)
{
    FILE *f = trace_file();
    if (!f)
        return;
    fprintf(f, "%s %s", kind, head);
    for (int i = 0; i < len && i < max; i++)
        fprintf(f, "%02x", data[i]);
    if (len > max)
        fprintf(f, "...(+%d)", len - max);
    fputc('\n', f);
    fflush(f);
}

/* Emit a phase marker in the neatcap format so native traces can be diffed
 * against vendor traces with re/tools/tracephase.py. */
static void trace_phase(const char *name, int cmd)
{
    FILE *f = trace_file();
    if (!f)
        return;
    fprintf(f, "### SNCmd(0x%x %s p5=0 p6=0)\n", cmd, name);
    fflush(f);
}

void nd1000_set_log(nd1000_log_fn fn) { log_fn = fn; }

static void dbg(int level, const char *fmt, ...)
{
    char msg[512];
    va_list ap;
    if (!log_fn)
        return;
    va_start(ap, fmt);
    vsnprintf(msg, sizeof(msg), fmt, ap);
    va_end(ap);
    log_fn(level, msg);
}

const char *nd1000_strerror(int s)
{
    switch (s) {
    case ND1000_OK: return "ok";
    case ND1000_EOF: return "end of page";
    case ND1000_ERR_IO: return "USB I/O error";
    case ND1000_ERR_NODEV: return "scanner not found";
    case ND1000_ERR_NOPAPER: return "no paper in the feeder";
    case ND1000_ERR_INVAL: return "invalid argument";
    case ND1000_ERR_NOMEM: return "out of memory";
    case ND1000_ERR_BUSY: return "device busy";
    case ND1000_ERR_CANCELLED: return "cancelled";
    }
    return "unknown error";
}

static void msleep(int ms)
{
    if (trace_file()) {
        fprintf(trace_fp, "Sleep %d\n", ms);
        fflush(trace_fp);
    }
    struct timespec ts = {ms / 1000, (ms % 1000) * 1000000L};
    while (nanosleep(&ts, &ts) && errno == EINTR)
        ;
}

/* ------------------------------------------------------------------------ */
/* USB primitives (ND-1000 uses the same register/bulk idioms as the NM-1000) */

static int ctrl_out(struct nd1000 *d, uint16_t value, uint16_t index, const uint8_t *data, uint16_t len)
{
    uint8_t req = len > 1 ? REQ_BUFFER : REQ_REGISTER;
    char head[64];
    snprintf(head, sizeof(head), "%02x %04x %04x %u ", req, value, index, len);
    trace_xfer("CO", head, data, len, 1 << 20);
    int r = libusb_control_transfer(d->h, 0x40, req, value, index, (uint8_t *)data, len, CTRL_TIMEOUT);
    if (r != len) {
        dbg(1, "control out %04x/%04x len %u failed: %s", value, index, len,
            r < 0 ? libusb_error_name(r) : "short");
        return ND1000_ERR_IO;
    }
    return ND1000_OK;
}

static int write_pairs(struct nd1000 *d, const uint8_t *pairs, int n)
{
    while (n > 0) {
        int k = n > 32 ? 32 : n;
        int r = ctrl_out(d, VAL_SET_REGISTER, 0, pairs, k * 2);
        if (r)
            return r;
        pairs += k * 2;
        n -= k;
    }
    return ND1000_OK;
}

static int write_reg(struct nd1000 *d, uint8_t reg, uint8_t val)
{
    uint8_t p[2] = {reg, val};
    return write_pairs(d, p, 1);
}

static int read_regs(struct nd1000 *d, uint8_t reg, uint8_t *out, int n)
{
    uint8_t buf[66];
    if (n < 1 || n > 64)
        return ND1000_ERR_INVAL;
    int r = libusb_control_transfer(d->h, 0xc0, REQ_BUFFER, VAL_GET_REGISTER, 0x22 | (reg << 8), buf, n + 1,
                                    CTRL_TIMEOUT);
    char head[64];
    snprintf(head, sizeof(head), "04 008e %04x %d -> ", 0x22 | (reg << 8), n + 1);
    trace_xfer("CI", head, buf, r > 0 ? r : 0, 4096);
    if (r != n + 1 || buf[n] != 0x55) {
        dbg(1, "register read 0x%02x x%d failed: %s", reg, n, r < 0 ? libusb_error_name(r) : "bad status");
        return ND1000_ERR_IO;
    }
    memcpy(out, buf, n);
    return ND1000_OK;
}

static int read_reg(struct nd1000 *d, uint8_t reg, uint8_t *val)
{
    return read_regs(d, reg, val, 1);
}

static int write_timing(struct nd1000 *d, uint8_t index, uint8_t val)
{
    return ctrl_out(d, VAL_TIMING, index, &val, 1);
}

static int bulk_header(struct nd1000 *d, int out, uint32_t addr, uint32_t len)
{
    uint8_t h[8];
    for (int i = 0; i < 4; i++) {
        h[i] = addr >> (8 * i);
        h[4 + i] = len >> (8 * i);
    }
    return ctrl_out(d, VAL_BUFFER, out ? 1 : 0, h, 8);
}

static int bulk_write(struct nd1000 *d, uint32_t addr, const uint8_t *data, uint32_t len)
{
    int n = 0, r;
    if ((r = bulk_header(d, 1, addr, len)))
        return r;
    char head[32];
    snprintf(head, sizeof(head), "%u ", len);
    trace_xfer("BO", head, data, len, 1 << 20);
    r = libusb_bulk_transfer(d->h, EP_OUT, (uint8_t *)data, len, &n, BULK_TIMEOUT);
    if (r || (uint32_t)n != len) {
        dbg(1, "bulk write %u bytes to %08x failed: %s", len, addr, libusb_error_name(r));
        return ND1000_ERR_IO;
    }
    return ND1000_OK;
}

static int bulk_read(struct nd1000 *d, uint32_t addr, uint8_t *data, uint32_t len)
{
    int n = 0, r;
    if ((r = bulk_header(d, 0, addr, len)))
        return r;
    r = libusb_bulk_transfer(d->h, EP_IN, data, len, &n, BULK_TIMEOUT);
    char head[32];
    snprintf(head, sizeof(head), "%u -> %d ", len, n);
    trace_xfer("BI", head, data, n, 64);
    if (r || (uint32_t)n != len) {
        dbg(1, "bulk read %u bytes from %08x failed: %s (got %d)", len, addr, libusb_error_name(r), n);
        return ND1000_ERR_IO;
    }
    return ND1000_OK;
}

/* Bulk read that tolerates a short transfer: the ND-1000 ends a side with a
 * short read (or a timeout after partial data). Returns 0 and sets *got. */
static int bulk_read_avail(struct nd1000 *d, uint32_t addr, uint8_t *data, uint32_t len, int *got)
{
    int n = 0, r;
    *got = 0;
    if ((r = bulk_header(d, 0, addr, len)))
        return r;
    r = libusb_bulk_transfer(d->h, EP_IN, data, len, &n, BULK_TIMEOUT);
    char head[32];
    snprintf(head, sizeof(head), "%u -> %d ", len, n);
    trace_xfer("BI", head, data, n, 64);
    if (r && !(r == LIBUSB_ERROR_TIMEOUT && n > 0)) {
        dbg(1, "bulk read %u bytes from %08x failed: %s (got %d)", len, addr, libusb_error_name(r), n);
        return ND1000_ERR_IO;
    }
    *got = n;
    return ND1000_OK;
}

/* ------------------------------------------------------------------------ */
/* Register programs (nd1000_tables.h)                                       */

struct prog_ctx {
    int lincnt; /* value for OP_LINCNT */
};

static int wait_motor(struct nd1000 *d)
{
    uint8_t st[3];
    int r;
    for (int i = 0; i < 3000; i++) {
        if ((r = read_regs(d, 0x40, st, 3)))
            return r;
        if (!(st[1] & 0x01))
            return ND1000_OK;
        if ((r = write_reg(d, 0x02, 0x58)))
            return r;
        msleep(5);
    }
    dbg(1, "timeout waiting for the motor to stop");
    return ND1000_ERR_IO;
}

static int run_prog(struct nd1000 *d, const uint8_t *p, const struct prog_ctx *ctx)
{
    int r = 0;
    for (;;) {
        switch (*p++) {
        case OP_END:
            return ND1000_OK;
        case OP_W: {
            int n = *p++;
            r = write_pairs(d, p, n);
            p += 2 * n;
            break;
        }
        case OP_SLEEP:
            msleep(p[0] | p[1] << 8);
            p += 2;
            break;
        case OP_8C:
            r = write_timing(d, p[0], p[1]);
            p += 2;
            break;
        case OP_BULK: {
            uint32_t addr = p[0] | p[1] << 8 | p[2] << 16 | (uint32_t)p[3] << 24;
            uint16_t len = p[4] | p[5] << 8;
            r = bulk_write(d, addr, p + 6, len);
            p += 6 + len;
            break;
        }
        case OP_LINCNT: {
            uint8_t w[6] = {0x25, ctx->lincnt >> 16, 0x26, ctx->lincnt >> 8, 0x27, ctx->lincnt};
            r = write_pairs(d, w, 3);
            break;
        }
        case OP_WAITMOTOR:
            r = wait_motor(d);
            break;
        case OP_CTRLW: {
            /* CO <req> <value> <index> <len> <data>: ND calibration/EEPROM
             * address write (value 0x8b). The 0x8a data read that follows is
             * captured as OP_BULKIN only when it is replayed. */
            uint16_t value = p[1] | p[2] << 8;
            uint16_t index = p[3] | p[4] << 8;
            uint8_t dlen = p[5];
            r = ctrl_out(d, value, index, p + 6, dlen);
            p += 6 + dlen;
            break;
        }
        case OP_BULKIN: {
            uint32_t addr = p[0] | p[1] << 8 | p[2] << 16 | (uint32_t)p[3] << 24;
            uint32_t len = p[4] | p[5] << 8 | p[6] << 16 | (uint32_t)p[7] << 24;
            uint8_t *tmp = malloc(len ? len : 1);
            if (!tmp)
                return ND1000_ERR_NOMEM;
            r = bulk_read(d, addr, tmp, len);
            free(tmp);
            p += 8;
            break;
        }
        case OP_CTRLR: {
            /* Replay a vendor register readback (CI 0x8e) at its captured
             * position: part of the write-then-poll handshake that paces the
             * motor/command register, not just a status query. */
            uint8_t tmp[64];
            r = read_regs(d, p[0], tmp, p[1]);
            p += 2;
            break;
        }
        case OP_AFECAL:
        case OP_SHADING:
            /* Not produced by the current inline-replay ND tables. */
            dbg(1, "unsupported ND opcode %d", p[-1]);
            return ND1000_ERR_INVAL;
        default:
            dbg(1, "bad program opcode %d", p[-1]);
            return ND1000_ERR_INVAL;
        }
        if (r)
            return r;
    }
}

/* ------------------------------------------------------------------------ */
/* Device lifecycle                                                          */

static int device_init(struct nd1000 *d)
{
    struct prog_ctx ctx = {0};
    return run_prog(d, prog_common_init, &ctx);
}

static int match_device(libusb_device *dev, int bus, int address)
{
    struct libusb_device_descriptor desc;
    if (libusb_get_device_descriptor(dev, &desc))
        return 0;
    if (desc.idVendor != ND1000_VENDOR || desc.idProduct != ND1000_PRODUCT)
        return 0;
    if (bus >= 0 && libusb_get_bus_number(dev) != bus)
        return 0;
    if (address >= 0 && libusb_get_device_address(dev) != address)
        return 0;
    return 1;
}

int nd1000_open(struct nd1000 **out, int bus, int address)
{
    struct nd1000 *d = calloc(1, sizeof(*d));
    libusb_device **list = NULL;
    libusb_device *found = NULL;
    struct libusb_device_descriptor desc;
    ssize_t n;
    int r;

    if (!d)
        return ND1000_ERR_NOMEM;
    if (libusb_init(&d->ctx)) {
        free(d);
        return ND1000_ERR_IO;
    }
    n = libusb_get_device_list(d->ctx, &list);
    for (ssize_t i = 0; i < n && !found; i++)
        if (match_device(list[i], bus, address))
            found = list[i];
    if (!found) {
        libusb_free_device_list(list, 1);
        libusb_exit(d->ctx);
        free(d);
        return ND1000_ERR_NODEV;
    }
    r = libusb_open(found, &d->h);
    libusb_get_device_descriptor(found, &desc);
    libusb_free_device_list(list, 1);
    if (r) {
        dbg(1, "cannot open scanner: %s", libusb_error_name(r));
        libusb_exit(d->ctx);
        free(d);
        return r == LIBUSB_ERROR_ACCESS ? ND1000_ERR_NODEV : ND1000_ERR_IO;
    }
    libusb_set_auto_detach_kernel_driver(d->h, 1);
    if ((r = libusb_claim_interface(d->h, 0))) {
        dbg(1, "cannot claim interface: %s", libusb_error_name(r));
        libusb_close(d->h);
        libusb_exit(d->ctx);
        free(d);
        return r == LIBUSB_ERROR_BUSY ? ND1000_ERR_BUSY : ND1000_ERR_IO;
    }
    if (desc.iSerialNumber <= 0 ||
        libusb_get_string_descriptor_ascii(d->h, desc.iSerialNumber, (uint8_t *)d->serial, sizeof(d->serial)) <= 0)
        snprintf(d->serial, sizeof(d->serial), "unknown");

    if ((r = device_init(d))) {
        nd1000_close(d);
        return r;
    }
    *out = d;
    return ND1000_OK;
}

void nd1000_close(struct nd1000 *d)
{
    static const uint8_t park[] = {0x03, 0x0f, 0x03, 0x8f, 0x6f, 0x00, 0x6d, 0x3f, 0x6b, 0x00};
    if (!d)
        return;
    if (d->scanning)
        nd1000_finish(d);
    write_pairs(d, park, sizeof(park) / 2);
    free(d->chunk);
    free(d->rawbuf);
    if (d->bulk)
        fclose(d->bulk);
    libusb_release_interface(d->h, 0);
    libusb_close(d->h);
    libusb_exit(d->ctx);
    free(d);
}

const char *nd1000_serial(struct nd1000 *d) { return d->serial; }

const int *nd1000_resolutions(void)
{
    static const int res[] = {150, 200, 300, 600, 0};
    return res;
}

/* ND paper status: write 0a=20, then reg 0x40. From the vendor traces a sheet
 * reads 0x70 and an empty feeder 0xf0, i.e. bit 0x80 set means empty. */
int nd1000_paper_present(struct nd1000 *d)
{
    uint8_t v;
    int r;
    if ((r = write_reg(d, 0x0a, 0x20)) || (r = read_reg(d, 0x40, &v)))
        return r;
    return !(v & 0x80);
}

/* ------------------------------------------------------------------------ */
/* Scanning                                                                  */

static const struct nd1000_mode *find_mode(int dpi)
{
    for (size_t i = 0; i < sizeof(nd1000_modes) / sizeof(nd1000_modes[0]); i++)
        if (nd1000_modes[i].dpi == dpi)
            return &nd1000_modes[i];
    return NULL;
}

/* If ND1000_BULK_DIR is set, capture the raw image-FIFO byte stream for each
 * side to <dir>/raw_<dpi>_<color|gray>_s<side>.bin. Used to reverse-engineer
 * the per-mode line packing (see re/README.md). */
static void dump_open(struct nd1000 *d)
{
    if (d->bulk) {
        fclose(d->bulk);
        d->bulk = NULL;
    }
    const char *dir = getenv("ND1000_BULK_DIR");
    if (!dir || !*dir || !d->mode)
        return;
    char path[1024];
    snprintf(path, sizeof(path), "%s/raw_%d_%s_s%d.bin", dir, d->mode->dpi,
             d->mode->color ? "color" : "gray", d->side);
    d->bulk = fopen(path, "wb");
    if (!d->bulk)
        dbg(1, "cannot open raw dump %s", path);
}

int nd1000_start(struct nd1000 *d, int dpi, int max_height_mm, struct nd1000_scan_info *info)
{
    const struct nd1000_mode *m = find_mode(dpi);
    struct prog_ctx ctx;
    int r;

    if (!m || max_height_mm <= 0 || max_height_mm > 900)
        return ND1000_ERR_INVAL;
    if (d->scanning)
        return ND1000_ERR_BUSY;

    d->mode = m;
    d->bpl = m->pixels * (m->color ? 3 : 1);
    d->lines_max = (int)(((long)max_height_mm * dpi * 10 + 127) / 254);
    d->lines_done = 0;
    d->data_seen = 0;
    d->side = 0;
    d->edge_seen = 0;
    if (d->sides < 1)
        d->sides = 1;
    d->chunk_lines = ND_READ_BYTES / d->bpl;
    if (d->chunk_lines < 1)
        d->chunk_lines = 1;
    free(d->chunk);
    d->chunk = malloc((size_t)d->chunk_lines * d->bpl);
    if (!d->chunk)
        return ND1000_ERR_NOMEM;

    /* 150 dpi colour is the one mode whose image assembly is fully recovered
     * and validated (re/README.md); use the raw-framed path there. */
    d->raw_bpl = (m->color && dpi == 150) ? ND1000_RAW_BPL_150_COLOR : 0;
    switch (dpi) {
    case 150: d->raw_reclen = 7992; break;
    case 200: d->raw_reclen = 10584; break;
    case 300: d->raw_reclen = 15876; break;
    case 600: d->raw_reclen = 31752; break;
    default: d->raw_reclen = 0; break;
    }
    d->warmup_left = d->raw_bpl ? ND1000_WARMUP_LINES : 0;
    d->rawfill = 0;
    free(d->rawbuf);
    d->rawbuf = d->raw_bpl ? malloc((size_t)d->raw_bpl * 64) : NULL;
    if (d->raw_bpl && !d->rawbuf)
        return ND1000_ERR_NOMEM;

    /* Colour scans advance the line counter per colour plane, as on the
     * NM-1000; the exact ND factor is unverified. */
    ctx.lincnt = d->lines_max * (m->color ? 3 : 1);
    if (ctx.lincnt > 0xffffff)
        return ND1000_ERR_INVAL;

    /* A partially applied program can leave the motor/lamp active. Keep the
     * stop sequence eligible from the first device write onward. */
    d->scanning = 1;
    trace_phase("set-params", 2);
    if ((r = run_prog(d, m->setparams, &ctx)))
        goto failed_start;
    trace_phase("load-calib", 4);
    if ((r = run_prog(d, m->calib, &ctx)))
        goto failed_start;
    trace_phase("lamp", 9);
    if ((r = run_prog(d, prog_lamp_on, &ctx)))
        goto failed_start;
    trace_phase("start", 5);
    if ((r = run_prog(d, m->start, &ctx)))
        goto failed_start;
    d->side = 0;
    dump_open(d);
    if (info) {
        info->dpi = dpi;
        info->color = m->color;
        info->pixels = m->pixels;
        info->bytes_per_line = d->bpl;
        info->max_lines = d->lines_max;
    }
    return ND1000_OK;

failed_start:
    if (nd1000_finish(d) != ND1000_OK)
        dbg(1, "failed to stop after scan setup error");
    return r;
}

/* Decoded read protocol (validated against re/traces/nd/scan_150_24.log):
 *  - Each SNCmd(6) call issues up to two bulk reads from the image FIFO
 *    (e.g. 259740 + 251748 bytes at 150 dpi).
 *  - End of a side is signalled by a *short* bulk read (the front-end call
 *    got 215784 bytes and returned 0x1001; the back end returned 0xe10d).
 *  - Register 0x41 bit 0x40 tracks the side: 0x8d = front, 0xcd = back.
 *  - The driver buffers the front image in TopImage.raw between the two
 *    sides, so one nd1000_start covers both sides of a sheet. */
void nd1000_set_duplex(struct nd1000 *d, int enabled)
{
    d->sides = enabled ? 2 : 1;
}

int nd1000_side(struct nd1000 *d) { return d->side; }

int nd1000_trim_trailing_blank(const uint8_t *buf, int bpl, int lines)
{
    /* Exact blank rows (all 0x00 / 0xff) the engine pads to the programmed
     * height. */
    while (lines > 0) {
        const uint8_t *row = buf + (size_t)(lines - 1) * bpl;
        int blank = 1;
        for (int i = 0; i < bpl; i++) {
            if (row[i] != 0x00 && row[i] != 0xff) {
                blank = 0;
                break;
            }
        }
        if (!blank)
            break;
        lines--;
    }
    /* Over-scan past the end of the sheet: once the paper leaves the CIS the
     * sensor sees the dark background, so the tail rows contain no bright
     * (paper) pixel. Crop them from content; if the whole image is dark, leave
     * it unchanged rather than return an empty page. */
    int cut = lines;
    while (cut > 0) {
        const uint8_t *row = buf + (size_t)(cut - 1) * bpl;
        int bright = 0;
        for (int i = 0; i < bpl; i++) {
            if (row[i] >= ND1000_PAPER_MAX) {
                bright = 1;
                break;
            }
        }
        if (bright)
            break;
        cut--;
    }
    if (cut > 0)
        lines = cut;
    return lines;
}

static int advance_side(struct nd1000 *d)
{
    d->side++;
    d->lines_done = 0;
    d->rawfill = 0;
    if (d->raw_bpl)
        d->warmup_left = ND1000_WARMUP_LINES;
    dump_open(d);
    return d->side >= d->sides ? ND1000_EOF : ND1000_SIDE_DONE;
}

/* Recovered from neatadfscanner_x64.dll (see re/README.md) and verified
 * byte-for-byte against the vendor 150 dpi colour output. Each 16-bit sample
 * carries two adjacent pixels: the sample phases (j%3) feed the left, middle
 * and right thirds of the row, with the high/low byte taking opposite parities.
 * Columns 430 and 860 have no raw source and are the mean of their neighbours. */
int nd1000_unpack_150_color(const uint8_t *raw, uint8_t *out, int pixels)
{
    if (pixels != 1272)
        return -1;
    memset(out, 0xff, (size_t)pixels * 3);
    for (int ch = 0; ch < 3; ch++) {
        const uint8_t *s = raw + (size_t)((3 + ch) * 666 + 15) * 2;
#define SAMP(j) ((unsigned)s[(size_t)(j) * 2] | ((unsigned)s[(size_t)(j) * 2 + 1] << 8))
        for (int k = 0; k <= 214; k++) {
            out[(size_t)(2 * k + 1) * 3 + ch] = (uint8_t)(SAMP(3 * k + 2) >> 8);   /* left odd */
            out[(size_t)(2 * k) * 3 + ch] = (uint8_t)(SAMP(3 * k + 1) & 0xff);     /* left even */
            out[(size_t)(2 * k + 431) * 3 + ch] = (uint8_t)(SAMP(3 * k + 1) >> 8); /* middle odd */
            if (k >= 1)
                out[(size_t)(2 * k + 430) * 3 + ch] = (uint8_t)(SAMP(3 * k + 0) & 0xff); /* middle even */
        }
        for (int k = 0; k <= 205; k++)
            out[(size_t)(2 * k + 861) * 3 + ch] = (uint8_t)(SAMP(3 * k + 2) & 0xff); /* right odd */
        for (int k = 1; k <= 205; k++)
            out[(size_t)(2 * k + 860) * 3 + ch] = (uint8_t)(SAMP(3 * k + 0) >> 8);   /* right even */
#undef SAMP
    }
    for (int ch = 0; ch < 3; ch++)
        for (int x = 430; x <= 860; x += 430)
            out[(size_t)x * 3 + ch] =
                (uint8_t)((out[(size_t)(x - 1) * 3 + ch] + out[(size_t)(x + 1) * 3 + ch]) / 2);
    return 0;
}

/* ------------------------------------------------------------------------ */
/* Generic raw decoder (see re/README.md and E_findings.md).
 *
 * Every 16-bit sample packs two adjacent 8-bit pixels (Lo = v&0xFF,
 * Hi = v>>8). For 200/300/600 a row is a stride-3 circular read of a byte
 * window with a per-line deskew offset; 150 dpi uses an explicit three-segment
 * packing (nd1000_unpack_150_color). Front = group B (sectors 3-5), back =
 * group A (0-2); both sides are carried in the same record stream. */

enum { ND_PACK_WINDOW, ND_PACK_150, ND_PACK_200 };

struct nd_pack_cfg {
    int dpi, side, pack;
    int sector, sync, mp, width;
    int rec0, step, period, b0, sign, sbase, rec_skip, wedge_dc, reset_wedge_zero;
};

static const struct nd_pack_cfg nd_packs[] = {
    /* dpi side  pack            sector sync  mp   width rec0 step per   b0   sign sbase skip wedge reset */
    {150, 0, ND_PACK_150,         666,  15,    0, 1272,  70,  0,  0,    0,   0,   0,    0,    0,    0},
    {200, 0, ND_PACK_200,         882,  21, 1718, 1700,   0,  0,  0,    0,   0,   0,    0,    0,    0},
    {300, 0, ND_PACK_WINDOW,     1323,  30, 2579, 2548, 140, 12, 32, 2578,   3,   3,    0,   12,    1},
    {300, 1, ND_PACK_WINDOW,     1323,  30, 2579, 2548,   0,-12, 636,2470,  -3,   0,    1,  -12,    0},
    {600, 0, ND_PACK_WINDOW,     2646,  29, 5159, 5100, 280, 36, 16,    1,   3,   3,    0,   36,    1},
};

static int pmod(int a, int m)
{
    int r = a % m;
    return r < 0 ? r + m : r;
}

/* Interleaved bytes (Lo,Hi,...) of sector `sidx` after `sync` samples. */
static void nd_get_sec(const uint8_t *raw, size_t nrec, long rec, int sector,
                       int sidx, int sync, uint8_t *d)
{
    int dn = 2 * (sector - sync);
    if (rec < 0 || (size_t)rec >= nrec) {
        memset(d, 0, dn);
        return;
    }
    const uint8_t *base = raw + ((size_t)rec * 6 + sidx) * (size_t)sector * 2 + (size_t)sync * 2;
    memcpy(d, base, dn);
}

static void nd_window_row(const uint8_t *raw, size_t nrec, const struct nd_pack_cfg *c,
                          uint8_t *p, int r, int ch, uint8_t *cur, uint8_t *nxt)
{
    int sector = c->sector, sync = c->sync, MP = c->mp, W = c->width;
    int u = r % c->period;
    long rec = c->rec0 + r + (c->rec_skip ? r / c->period : 0);
    int b = pmod(c->b0 + c->step * u, MP);
    int sidx = c->sbase + ch;

    nd_get_sec(raw, nrec, rec, sector, sidx, sync, cur);
    for (int x = 0; x < W; x++)
        p[x] = cur[pmod(c->sign * x + b, MP)];

    int cols = (c->step < 0 ? -c->step : c->step) / 3;
    int xstart = W - cols * (u + 1);

    /* Seam columns: the first column after (forward) / before (mirrored) each
     * circular wrap, except the wrap at the page edge. */
    for (int x = 1; x < W; x++) {
        int ix = pmod(c->sign * x + b, MP);
        int ip = pmod(c->sign * (x - 1) + b, MP);
        int wrap = c->sign > 0 ? ix < ip : ix > ip;
        if (!wrap)
            continue;
        int yy = c->sign > 0 ? x : x - 1;
        int hi = c->sign < 0 ? xstart - 2 : xstart;
        int lim = hi < W - 1 ? hi : W - 1;
        if (yy > 1 && yy < lim)
            p[yy] = (uint8_t)((p[yy - 1] + p[yy + 1]) / 2);
    }

    /* Deskew wedge: continue into the next record (or the page edge). */
    if (xstart < W) {
        if (c->reset_wedge_zero && u == c->period - 1) {
            memset(p + xstart, 0, (size_t)(W - xstart));
        } else {
            nd_get_sec(raw, nrec, rec + 1, sector, sidx, sync, nxt);
            int bc = pmod(b + c->wedge_dc, MP);
            for (int x = xstart; x < W; x++)
                p[x] = nxt[pmod(c->sign * (x - W) + bc, MP)];
        }
    }
}

static void nd_200_row(const uint8_t *raw, size_t nrec, uint8_t *outrow, int r,
                       uint8_t *cur, uint8_t *prv)
{
    const int MP = 1718, sector = 882, sync = 21, W = 1700;
    int t = r % 98;
    long rec = 92 + r - r / 98;
    uint8_t p[1700];
    for (int ch = 0; ch < 3; ch++) {
        if (t <= 48) { /* group B (sectors 3-5); t=48 is the B->A switch row */
            int b = pmod(1717 - 12 * t, MP);
            nd_get_sec(raw, nrec, rec, sector, 3 + ch, sync, cur);
            nd_get_sec(raw, nrec, rec - 1, sector, 3 + ch, sync, prv);
            for (int x = 0; x < W; x++)
                p[x] = cur[pmod(3 * x + b, MP)];
            int we = 4 * t;
            for (int x = 0; x < we && x < W; x++)
                p[x] = prv[pmod(3 * x + b - 42, MP)];
            int seams[2] = {we + 573, we + 1146};
            for (int s = 0; s < 2; s++)
                if (seams[s] > 0 && seams[s] < W)
                    p[seams[s]] = (uint8_t)((p[seams[s] - 1] + p[seams[s] + 1]) / 2);
            if (t == 0)
                p[0] = 0;
            /* The switch row is valid only over its wedge; black the rest. */
            if (t == 48 && we < W)
                memset(p + we, 0, (size_t)(W - we));
        } else if (t >= 49) { /* group A, sectors 0-2, mirrored; t=97 is A->B */
            int b = pmod(1066 + 12 * t, MP);
            nd_get_sec(raw, nrec, rec, sector, 0 + ch, sync, cur);
            nd_get_sec(raw, nrec, rec - 1, sector, 0 + ch, sync, prv);
            for (int x = 0; x < W; x++)
                p[x] = cur[pmod(-3 * x + b, MP)];
            int we = 4 * (t - 49);
            for (int x = 0; x < we && x < W; x++)
                p[x] = prv[pmod(-3 * x + b + 42, MP)];
            for (int x = we - 7; x < we; x++)
                if (x >= 0 && x < W)
                    p[x] = 0;
            int seams[2] = {we + 551, we + 1124};
            for (int s = 0; s < 2; s++)
                if (seams[s] >= 1 && seams[s] < W - 1)
                    p[seams[s]] = (uint8_t)((p[seams[s] - 1] + p[seams[s] + 1]) / 2);
            if (t == 97 && we < W)
                memset(p + we, 0, (size_t)(W - we));
        } else { /* unreachable; kept for safety */
            memset(p, 0, W);
        }
        for (int x = 0; x < W; x++)
            outrow[x * 3 + ch] = p[x];
    }
}

int nd1000_decode_page(int dpi, int side, const uint8_t *raw, size_t nbytes,
                       uint8_t *out, int width, int height)
{
    const struct nd_pack_cfg *c = NULL;
    for (size_t i = 0; i < sizeof(nd_packs) / sizeof(nd_packs[0]); i++)
        if (nd_packs[i].dpi == dpi && nd_packs[i].side == side)
            c = &nd_packs[i];
    if (!c || !raw || !out || c->width != width || height <= 0 || height > 100000)
        return ND1000_ERR_INVAL;

    size_t reclen = (size_t)6 * c->sector * 2;
    size_t nrec = nbytes / reclen;
    long last = c->pack == ND_PACK_200
        ? 92L + height - 1 - (height - 1) / 98
        : (long)c->rec0 + height - 1 + (c->rec_skip ? (height - 1) / c->period : 0);
    if (last < 0 || (size_t)last >= nrec)
        return ND1000_ERR_INVAL;
    int dlen = 2 * (c->sector - c->sync);
    uint8_t *cur = malloc(dlen), *nxt = malloc(dlen), *prv = malloc(dlen);
    if (!cur || !nxt || !prv) {
        free(cur); free(nxt); free(prv);
        return -2;
    }

    if (c->pack == ND_PACK_150) {
        for (int r = 0; r < height; r++)
            nd1000_unpack_150_color(raw + (size_t)(r + c->rec0) * reclen,
                                    out + (size_t)r * width * 3, width);
    } else if (c->pack == ND_PACK_200) {
        for (int r = 0; r < height; r++)
            nd_200_row(raw, nrec, out + (size_t)r * width * 3, r, cur, prv);
    } else {
        uint8_t p[5100];
        for (int r = 0; r < height; r++) {
            uint8_t *orow = out + (size_t)r * width * 3;
            for (int ch = 0; ch < 3; ch++) {
                nd_window_row(raw, nrec, c, p, r, ch, cur, nxt);
                for (int x = 0; x < width; x++)
                    orow[x * 3 + ch] = p[x];
            }
        }
    }
    free(cur); free(nxt); free(prv);
    return 0;
}

/* The decoded/vendor raster still shifts horizontally each line. The 300 dpi
 * front shifts 4 pixels per row and resets after 32 lines; applying the
 * inverse periodic shift makes the same-sheet text legible. The back and
 * other resolutions use the measured periods and slopes below. Keep this
 * separate from raw byte assembly so each stage can be validated alone. */
int nd1000_realign_page(int dpi, int side, uint8_t *rgb, int width, int height)
{
    int period, slope;
    size_t bpl;
    uint8_t *rowbuf;

    if (!rgb || width <= 0 || height < 0 ||
        width != (((long long)dpi * 85 / 10) & ~3LL) || (size_t)width > SIZE_MAX / 3)
        return ND1000_ERR_INVAL;
    bpl = (size_t)width * 3;
    if (dpi == 150 && side == 0)
        return ND1000_OK;
    if (dpi == 200 && side == 0) {
        period = 98; slope = -4;
    } else if (dpi == 300 && side == 0) {
        period = 32; slope = 4;
    } else if (dpi == 300 && side == 1) {
        period = 636; slope = 4;
    } else if (dpi == 600 && side == 0) {
        period = 16; slope = 12;
    } else {
        return ND1000_ERR_INVAL;
    }
    rowbuf = malloc(bpl);
    if (!rowbuf)
        return ND1000_ERR_NOMEM;
    for (int y = 0; y < height; y++) {
        uint8_t *row = rgb + (size_t)y * bpl;
        int shift = (slope * (y % period)) % width;
        if (shift < 0)
            shift += width;
        if (!shift)
            continue;
        memcpy(rowbuf, row + (size_t)(width - shift) * 3, (size_t)shift * 3);
        memcpy(rowbuf + (size_t)shift * 3, row, (size_t)(width - shift) * 3);
        memcpy(row, rowbuf, bpl);
    }
    free(rowbuf);

    /* The 200 dpi dual-array mode leaves a dark array-switch line every 98
     * rows (the vendor capture has them too). Smooth each switch row from its
     * neighbours so the page has no visible horizontal band. */
    if (dpi == 200) {
        for (int y = 1; y + 1 < height; y++) {
            if (y % period != 48 && y % period != 97)
                continue;
            uint8_t *row = rgb + (size_t)y * bpl;
            const uint8_t *prev = row - bpl, *next = row + bpl;
            for (size_t i = 0; i < bpl; i++)
                row[i] = (uint8_t)(((unsigned)prev[i] + next[i]) / 2);
        }
    }
    return ND1000_OK;
}

static const struct nd_pack_cfg *find_pack(int dpi, int side)
{
    for (size_t i = 0; i < sizeof(nd_packs) / sizeof(nd_packs[0]); i++)
        if (nd_packs[i].dpi == dpi && nd_packs[i].side == side)
            return &nd_packs[i];
    return NULL;
}

int nd1000_decode_height(int dpi, int side, size_t nbytes)
{
    const struct nd_pack_cfg *c = find_pack(dpi, side);
    if (!c)
        return -1;
    size_t nrec = nbytes / ((size_t)6 * c->sector * 2);
    int h = 0;
    while (h < 100000) {
        long rec = c->pack == ND_PACK_200 ? 92L + h - h / 98
                   : (long)c->rec0 + h + (c->rec_skip ? h / c->period : 0);
        if ((size_t)rec >= nrec)
            break;
        h++;
    }
    return h;
}

void nd1000_set_cancel(struct nd1000 *d, int (*cb)(void *ref), void *ref)
{
    d->cancelled = cb;
    d->cancel_ref = ref;
}

/* Drain the whole image FIFO for one physical pass. All sides of a sheet are
 * carried in the same record stream, so this stops only when the device has
 * no more data (short/zero bulk read). */
int nd1000_read_all(struct nd1000 *d, uint8_t **raw, size_t *len)
{
    size_t cap = (size_t)d->raw_bpl * 64, used = 0;
    uint8_t *buf;
    *raw = NULL;
    *len = 0;
    if (!d->scanning)
        return ND1000_ERR_INVAL;
    if (cap < 65536)
        cap = 65536;
    buf = malloc(cap);
    if (!buf)
        return ND1000_ERR_NOMEM;
    /* Without trailing-edge detection the device keeps scanning far past the
     * sheet; bound the drain to the requested height (plus warm-up margin) so
     * we neither read gigabytes nor leave the ASIC mid-scan. */
    size_t maxbytes = 0;
    if (d->raw_reclen > 0 && d->lines_max > 0)
        maxbytes = (size_t)(d->lines_max + 512) * d->raw_reclen;
    for (;;) {
        if (d->cancelled && d->cancelled(d->cancel_ref)) {
            free(buf);
            return ND1000_ERR_CANCELLED;
        }
        size_t headroom = (size_t)(1u << 20);
        if ((size_t)d->raw_bpl > headroom)
            headroom = (size_t)d->raw_bpl;
        if (cap - used < headroom) {
            size_t ncap = cap * 2 + headroom;
            uint8_t *nb = realloc(buf, ncap);
            if (!nb) { free(buf); return ND1000_ERR_NOMEM; }
            buf = nb; cap = ncap;
        }
        int got = 0;
        /* The device fills the requested length until the sheet ends; the
         * final transfer is short. Never issue a read with no data behind it
         * (it locks the ASIC). A quantum below the vendor's ~250 KiB avoids
         * requesting more than is buffered while still ending on a short read. */
        uint32_t want = 131072u;
        int r = bulk_read_avail(d, SCAN_FIFO, buf + used, want, &got);
        if (r) { free(buf); return r; }
        if (got <= 0) {
            /* A zero-length read is not a verified end-of-sheet marker on
             * this ASIC. Report an incomplete pass and let finish stop it. */
            free(buf);
            return used ? ND1000_ERR_IO : ND1000_ERR_NOPAPER;
        }
        if (d->bulk)
            fwrite(buf + used, 1, (size_t)got, d->bulk);
        used += (size_t)got;
        d->data_seen = 1;
        if ((uint32_t)got < want)
            break;   /* short transfer = end of sheet */
        if (maxbytes && used >= maxbytes)
            break;
    }
    d->rawfill = 0;
    if (used == 0) {
        free(buf);
        return d->data_seen ? ND1000_EOF : ND1000_ERR_NOPAPER;
    }
    *raw = buf;
    *len = used;
    return ND1000_OK;
}

/* Raw-framed read: accumulate raw FIFO lines (each ND1000_RAW_BPL_150_COLOR
 * bytes) and unpack them into RGB output lines. Used for the validated 150 dpi
 * colour mode; other modes keep the legacy line-sized path below. */
static int nd1000_read_raw(struct nd1000 *d, uint8_t *buf, int max_lines, int *lines)
{
    int made = 0, ended = 0, r;
    size_t cap = (size_t)d->raw_bpl * 64;
    *lines = 0;
    while (made < max_lines && d->lines_done + made < d->lines_max) {
        while (d->rawfill >= (size_t)d->raw_bpl &&
               made < max_lines && d->lines_done + made < d->lines_max) {
            if (d->warmup_left > 0) {
                d->warmup_left--;
            } else {
                if (nd1000_unpack_150_color(d->rawbuf, buf + (size_t)made * d->bpl,
                                            d->mode->pixels) == 0)
                    made++;
            }
            d->rawfill -= (size_t)d->raw_bpl;
            memmove(d->rawbuf, d->rawbuf + d->raw_bpl, d->rawfill);
        }
        if (made >= max_lines || d->lines_done + made >= d->lines_max)
            break;
        int got = 0;
        size_t before = d->rawfill;
        r = bulk_read_avail(d, SCAN_FIFO, d->rawbuf + d->rawfill,
                            (uint32_t)(cap - d->rawfill), &got);
        if (r)
            return r;
        if (got <= 0) {
            ended = 1;
            break;
        }
        if (d->bulk)
            fwrite(d->rawbuf + before, 1, (size_t)got, d->bulk);
        d->data_seen = 1;
        d->rawfill += (size_t)got;
    }
    d->lines_done += made;
    *lines = made;
    if (made > 0)
        return ND1000_OK;
    if (ended) {
        if (!d->data_seen)
            return ND1000_ERR_NOPAPER;
        return advance_side(d);
    }
    return advance_side(d);
}

int nd1000_read(struct nd1000 *d, uint8_t *buf, int max_lines, int *lines)
{
    int want, got, r;

    *lines = 0;
    if (!d->scanning)
        return ND1000_ERR_INVAL;
    if (d->side >= d->sides)
        return ND1000_EOF;
    if (d->raw_bpl)
        return nd1000_read_raw(d, buf, max_lines, lines);

    want = d->lines_max - d->lines_done;
    if (want > max_lines)
        want = max_lines;
    if (want > d->chunk_lines)
        want = d->chunk_lines;
    if (want <= 0)
        return advance_side(d);

    r = bulk_read_avail(d, SCAN_FIFO, d->chunk, (uint32_t)want * d->bpl, &got);
    if (r)
        return r;
    if (d->bulk && got > 0)
        fwrite(d->chunk, 1, (size_t)got, d->bulk);
    if (got <= 0) {
        /* No data at all before anything was read: empty feeder. After data,
         * a short/zero read ends the current side. */
        if (!d->data_seen)
            return ND1000_ERR_NOPAPER;
        return advance_side(d);
    }

    int l = got / d->bpl;
    int px = d->mode->pixels;
    for (int i = 0; i < l; i++) {
        const uint8_t *src = d->chunk + (size_t)i * d->bpl;
        uint8_t *dst = buf + (size_t)i * d->bpl;
        if (d->mode->color) {
            /* The NM-1000 FIFO delivers colour lines as R, G, B planes. */
            for (int x = 0; x < px; x++) {
                dst[3 * x] = src[x];
                dst[3 * x + 1] = src[px + x];
                dst[3 * x + 2] = src[2 * px + x];
            }
        } else {
            memcpy(dst, src, px);
        }
    }
    d->lines_done += l;
    d->data_seen = 1;
    *lines = l;

    /* The vendor traces show reg 0x40 bit 6 rising when the 24-bit event
     * counter at 0x4b latches. Observe, but do not change the scan length
     * until this is confirmed on native hardware at more than one DPI. */
    if (d->side == 0 && !d->edge_seen) {
        uint8_t sensor, event[3], distance[2];
        if (read_reg(d, 0x40, &sensor) == ND1000_OK && (sensor & 0x40) &&
            read_regs(d, 0x4b, event, 3) == ND1000_OK &&
            read_regs(d, 0x92, distance, 2) == ND1000_OK) {
            unsigned count = (unsigned)event[0] << 16 | (unsigned)event[1] << 8 | event[2];
            unsigned gap = (unsigned)distance[0] << 8 | distance[1];
            if (count) {
                d->edge_seen = 1;
                dbg(1, "paper edge: status=%02x event=%u distance=%u candidate=%u lines (delivered=%d)",
                    sensor, count, gap, (2 * count + gap + 6) / 12, d->lines_done);
            }
        }
    }

    /* A short read marks the end of the current side. The ND scan engine runs
     * to the programmed line count (ND_READ_BYTES chunks + a short tail), so
     * this normally fires only at the programmed height. The vendor's ~1600
     * line stop comes from its own trailing-edge handling; reg 0x41 does not
     * carry the front sensor bit (it stays 0x85/0x8d in native traces), so
     * that remains to be decoded. */
    if (got < want * d->bpl)
        return advance_side(d);
    return ND1000_OK;
}

/* Advance the paper by replaying the captured SNCmd(0x13) program `steps`
 * times. Each replay runs two fixed microstep moves. The vendor ignores the
 * step argument (the capture is identical for p6=300 and p6=1000). This is the
 * feed/grab direction: it pulls a sheet into the machine, not out. */
int nd1000_feed(struct nd1000 *d, int steps)
{
    struct prog_ctx ctx = {0};
    if (steps <= 0 || steps > 64)
        return ND1000_ERR_INVAL;
    if (d->scanning)
        return ND1000_ERR_BUSY;
    if (prog_feed[0] == OP_END)
        return ND1000_ERR_INVAL; /* empty program (feed.log missing at build) */
    for (int i = 0; i < steps; i++) {
        int r = run_prog(d, prog_feed, &ctx);
        if (r)
            return r;
    }
    return ND1000_OK;
}

int nd1000_finish(struct nd1000 *d)
{
    struct prog_ctx ctx = {0};
    int r;
    if (!d->scanning)
        return ND1000_OK;
    trace_phase("stop", 7);
    r = run_prog(d, prog_stop, &ctx);
    /* Keep a failed stop eligible for one more attempt in nd1000_close(). */
    if (r == ND1000_OK)
        d->scanning = 0;
    return r;
}
