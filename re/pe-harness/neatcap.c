// SPDX-License-Identifier: GPL-2.0-or-later WITH SANE-exception
// Copyright (C) 2026 Evan McClain
/*
 * neatcap: drive Neat's own driver DLL through its SNCmd() entry point, the
 * same way its TWAIN data source does, and record the USB traffic.
 *
 *   neatcap DLL status
 *   neatcap DLL scan RES BPP OUT.pnm [WIDTH_PX HEIGHT_PX]
 *   neatcap DLL duplex RES BPP FRONT.pnm BACK.pnm
 *   neatcap DLL program RES BPP      (register programming only, no reads)
 *   neatcap DLL calibrate
 *   neatcap DLL feed STEPS
 *   neatcap DLL raw CMD P5 P6
 * For the ND-1000, set NEAT_USB_PID=0050 and pass the NeatDesk DLL.
 *
 * Trace goes to $NEAT_TRACE (default trace.log).
 */
#include <stdint.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "pe_harness.h"

typedef int (*__attribute__((ms_abi)) sncmd_t)(uint32_t cmd, uint32_t *params, void *buf, float *fp,
                                                 int p5, uint32_t p6);
static sncmd_t SNCmd;
static int nd1000;
static uint32_t nd_method = 0x80; /* 0x80 duplex, 0x800 simplex/ADF, 0x08 flatbed */
static int capture_only;          /* run the setup phases, then stop before reads */
static volatile sig_atomic_t stop_requested;

static void request_stop(int signal_number)
{
    (void)signal_number;
    stop_requested = 1;
}

static int cmd(const char *what, uint32_t c, uint32_t *params, void *buf, float *fp, int p5, uint32_t p6)
{
    trace("### SNCmd(0x%x %s p5=%d p6=%u)\n", c, what, p5, p6);
    int r = SNCmd(c, params, buf, fp, p5, p6);
    trace("### SNCmd(0x%x %s) = 0x%x\n", c, what, r);
    fprintf(stderr, "SNCmd(0x%x %s) = 0x%x\n", c, what, r);
    return r;
}

static int paper_present(void)
{
    int result = cmd("paper?", 0x16, NULL, NULL, NULL, 0, 0);
    /* NM: 0 = sheet; ND: 1 = sheet, 0xe107 = empty feeder.
     * Confirmed by the ND status traces with/without a sheet loaded. */
    if (nd1000 && result != 1 && result != 0xe107)
        return -1;
    return nd1000 ? result == 1 : result == 0;
}

static void eject(void)
{
    for (int i = 0; i < 12 && paper_present(); i++)
        cmd("feed", 0x13, NULL, NULL, NULL, 1, 1000);
}

static int write_pnm(const char *out, const uint8_t *data, int width, int lines, int bpl, int bpp)
{
    FILE *f = fopen(out, "wb");
    if (!f) {
        perror(out);
        return 1;
    }
    if (bpp == 24)
        fprintf(f, "P6\n%d %d\n255\n", width, lines);
    else if (bpp == 8)
        fprintf(f, "P5\n%d %d\n255\n", width, lines);
    else if (bpp == 16)
        fprintf(f, "P5\n%d %d\n65535\n", width, lines);
    else
        fprintf(f, "P4\n%d %d\n", width, lines);
    fwrite(data, 1, (size_t)bpl * lines, f);
    int bad = ferror(f);
    if (fclose(f) != 0)
        bad = 1;
    if (bad) {
        fprintf(stderr, "error writing %s\n", out);
        return 1;
    }
    fprintf(stderr, "wrote %s: %dx%d, %d bpp\n", out, width, lines, bpp);
    return 0;
}

/* back_out is NULL for a single-sided scan; otherwise the ND duplex sheet's
 * second side is read into it after the first side reports 0x1001/0x1002. */
static int do_scan(int res, int bpp, const char *out, const char *back_out, int width, int height)
{
    static uint32_t p[0x210];
    uint32_t lamp_params[2] = {0};
    int bpl, r;

    int paper = paper_present();
    if (paper < 0) {
        fprintf(stderr, "failed to read the feeder status\n");
        return 1;
    }
    if (!paper && !getenv("NEAT_NOPAPER")) {
        fprintf(stderr, "no paper detected; insert a sheet\n");
        return 1;
    }
    width &= bpp == 1 ? ~31 : ~3;
    memset(p, 0, sizeof(p));
    /* NeatADFScanner64.ds selects 0x80 for its ADF mode (0x800 for the
     * other feeder path); NM-1000 uses 0x08. With 0x08 on the ND the sheet
     * was detected but no motor movement occurred. */
    p[0] = nd1000 ? nd_method : 8;
    p[1] = bpp;
    p[2] = res;
    p[3] = res;
    double gamma = 1.6;
    if (nd1000) {
        /* Vendor NeatADFScanner64.ds block: mostly zero. Rect = {0,0,width,gap}
         * where width is the sensor line width and gap is dpi*0x1e (0xf for
         * 600 dpi) rounded to 16. Trailing word at 0x8ac = 4. */
        int w = (int)(res * 8.5);
        if (bpp == 1)
            w -= w % 0x60;
        else {
            w += 0xb;
            w -= w % 0x18;
        }
        int gap = (res >= 600 ? res * 0xf : res * 0x1e) & 0xfff0;
        p[4] = 0;
        p[5] = 0;
        p[6] = (uint32_t)w;
        p[7] = (uint32_t)gap;
        memcpy(&p[8], &gamma, 8);
        p[0x22b] = 4; /* byte offset 0x8ac */
    } else {
        p[4] = 0;
        p[5] = 0;
        p[6] = width;
        p[7] = height;
        memcpy(&p[8], &gamma, 8);
        p[10] = 0xe3f0 | (0x24u << 16);
        p[0xc] = 0x17f;
        p[0x20d] = 1;
        p[0x20f] = 4;
    }
    r = cmd("set-params", 2, p, NULL, NULL, 0, 0);
    if (r >= 0xe000)
        return 1;

    float bc[3] = {1.4f, 0, 0};
    cmd("bc-enable", 0x19, NULL, NULL, NULL, 1, 0);
    bc[0] = 16 * 0.1f; /* DS default: gamma slider 16 * 0.1, contrast 10?, brightness -5? */
    bc[1] = 10;
    bc[2] = -5;
    cmd("bc-set", 0x1a, NULL, NULL, bc, 0, 0);

    r = cmd("load-calib", 4, NULL, NULL, NULL, 0, 0);
    if (r != 0 || stop_requested)
        return 1;
    /* The ND DLL reads two words through SNCmd's fourth argument for cmd 9.
     * The NM DLL doesn't dereference this argument. */
    cmd("lamp", 9, NULL, NULL, nd1000 ? (float *)lamp_params : NULL, 1, 0);
    if (stop_requested) {
        cmd("lamp-off", 9, NULL, NULL, nd1000 ? (float *)lamp_params : NULL, 0, 0);
        return 1;
    }
    r = cmd("start", 5, NULL, NULL, NULL, 0, 0);
    if (r != 0 || stop_requested) {
        cmd("stop", 7, NULL, NULL, NULL, 0, 0);
        cmd("lamp-off", 9, NULL, NULL, nd1000 ? (float *)lamp_params : NULL, 0, 0);
        return 1;
    }
    if (capture_only) {
        /* Register-program capture: everything up to and including start is
         * in the trace; no paper or image read is needed. */
        cmd("stop", 7, NULL, NULL, NULL, 0, 0);
        cmd("lamp-off", 9, NULL, NULL, nd1000 ? (float *)lamp_params : NULL, 0, 0);
        return 0;
    }

    bpl = bpp == 1 ? (width + 7) / 8 : width * (bpp / 8);
    size_t total = (size_t)bpl * height;
    int sides = (nd1000 && back_out) ? 2 : 1;
    uint8_t *img = calloc(1, total * sides);
    if (!img) {
        fprintf(stderr, "out of memory allocating %zu-byte page\n", total * sides);
        cmd("stop", 7, NULL, NULL, NULL, 0, 0);
        cmd("lamp-off", 9, NULL, NULL, nd1000 ? (float *)lamp_params : NULL, 0, 0);
        return 1;
    }
    /* Keep each SNCmd read near the 244 KiB validated at 150 dpi, rather
     * than requesting almost 1 MiB in one call at 600 dpi. */
    int lines_per_read = 64;
    if (nd1000 && bpl * lines_per_read > 250000) {
        lines_per_read = 250000 / bpl;
        if (lines_per_read < 1)
            lines_per_read = 1;
    }
    size_t got[2] = {0, 0};
    int side = 0;
    for (;;) {
        if (stop_requested) {
            r = -1;
            break;
        }
        if (got[side] >= total) {
            if (side + 1 < sides) {
                side++;
                continue;
            }
            break;
        }
        size_t want = (size_t)bpl * lines_per_read;
        if (want > total - got[side])
            want = total - got[side];
        r = cmd("read", 6, NULL, img + (size_t)side * total + got[side], NULL, 0, (uint32_t)want);
        if (stop_requested) {
            r = -1;
            break;
        }
        if (r == 0) {
            got[side] += want;
            continue;
        }
        if (nd1000 && (r == 0x1001 || r == 0x1002 || r == 0xe10d)) {
            fprintf(stderr, "status 0x%x after side %d (%zu lines)\n", r, side, got[side] / bpl);
            if (side + 1 < sides && r != 0xe10d) {
                side++;
                continue;
            }
            r = 0;
            break;
        }
        fprintf(stderr, "read returned 0x%x after %zu lines\n", r, got[side] / bpl);
        break;
    }
    cmd("stop", 7, NULL, NULL, NULL, 0, 0);
    /* ND command 0x13 takes additional arguments that have not been mapped.
     * Never replay NM's eject loop on the ND (it crashes the vendor DLL). */
    if (!nd1000)
        eject();
    cmd("lamp-off", 9, NULL, NULL, nd1000 ? (float *)lamp_params : NULL, 0, 0);

    int rc = 0;
    if (r != 0 || got[0] == 0) {
        fprintf(stderr, "scan produced no complete image; sheet may need manual removal\n");
        rc = 1;
    } else {
        if (write_pnm(out, img, width, (int)(got[0] / bpl), bpl, bpp))
            rc = 1;
        if (sides > 1) {
            if (got[1] > 0)
                rc |= write_pnm(back_out, img + total, width, (int)(got[1] / bpl), bpl, bpp);
            else
                fprintf(stderr, "no back-side data captured\n");
        }
    }
    free(img);
    return rc;
}

int main(int argc, char **argv)
{
    struct sigaction stop_action = {.sa_handler = request_stop};
    sigemptyset(&stop_action.sa_mask);
    sigaction(SIGTERM, &stop_action, NULL);
    if (argc < 3) {
        fprintf(stderr, "usage: %s DLL status|scan|duplex|program|calibrate|feed ...\n", argv[0]);
        return 2;
    }
    const char *tp = getenv("NEAT_TRACE");
    const char *pid_env = getenv("NEAT_USB_PID");
    if (pid_env) {
        char *end;
        unsigned long pid = strtoul(pid_env, &end, 16);
        if (!*pid_env || *end || pid > 0xffff || !pe_set_usb_product((uint16_t)pid)) {
            fprintf(stderr, "NEAT_USB_PID must be 0001 or 0050\n");
            return 2;
        }
        nd1000 = pid == 0x0050;
    }
    const char *method_env = getenv("NEAT_ND_METHOD");
    if (method_env && *method_env) {
        char *end;
        unsigned long method = strtoul(method_env, &end, 16);
        if (*end || method > 0xffff) {
            fprintf(stderr, "NEAT_ND_METHOD must be a hex value\n");
            return 2;
        }
        nd_method = (uint32_t)method;
    }
    const char *nd_raw = getenv("NEAT_ND_RAW");
    if (nd1000 && (!strcmp(argv[2], "feed") || !strcmp(argv[2], "calibrate") ||
                   (!strcmp(argv[2], "raw") &&
                    !(nd_raw && !strcmp(nd_raw, "1"))))) {
        fprintf(stderr, "ND feed/calibration/raw commands need ND-specific argument mapping\n");
        return 2;
    }
    if (!pe_usb_accessible())
        return 1;
    trace_fp = fopen(tp ? tp : "trace.log", "w");
    bulk_dump_dir = getenv("NEAT_BULK_DIR");

    if (!pe_load(argv[1]))
        return 1;
    SNCmd = (sncmd_t)pe_export("SNCmd");
    if (!SNCmd) {
        fprintf(stderr, "SNCmd export not found\n");
        return 1;
    }

    int rc = 0;
    if (cmd("open", 1, NULL, NULL, NULL, 0, 0) != 0)
        return 1;
    cmd("connected?", 0x17, NULL, NULL, NULL, 0, 0);

    if (!strcmp(argv[2], "status")) {
        uint8_t buttons[2] = {0};
        cmd("buttons", 0x10, NULL, buttons, NULL, 0, 0);
        printf("paper=%d button0=%d button1=%d\n", paper_present(), buttons[0], buttons[1]);
    } else if (!strcmp(argv[2], "raw") && argc > 5) {
        /* raw CMD P5 P6: for commands that need no buffers */
        cmd("raw", strtoul(argv[3], NULL, 0), NULL, NULL, NULL, atoi(argv[4]), strtoul(argv[5], NULL, 0));
    } else if (!strcmp(argv[2], "feed") && argc > 3) {
        cmd("feed", 0x13, NULL, NULL, NULL, 1, atoi(argv[3]));
    } else if (!strcmp(argv[2], "calibrate")) {
        if (!paper_present()) {
            fprintf(stderr, "insert the calibration sheet first\n");
            rc = 1;
        } else {
            cmd("feed", 0x13, NULL, NULL, NULL, 1, 300);
            rc = cmd("calibrate", 3, NULL, NULL, NULL, 0, 0) != 0;
            cmd("lamp-off", 9, NULL, NULL, NULL, 0, 0);
            eject();
        }
    } else if (!strcmp(argv[2], "scan") && argc > 5) {
        int res = atoi(argv[3]), bpp = atoi(argv[4]);
        if (nd1000 && ((res != 150 && res != 200 && res != 300 && res != 600) || bpp != 24)) {
            fprintf(stderr, "ND scan supports 150, 200, 300 or 600 dpi in color\n");
            rc = 2;
            goto close_device;
        }
        int w = argc > 6 ? atoi(argv[6]) : (res * 85 / 10 & ~3);
        int h = argc > 7 ? atoi(argv[7]) : res * 11;
        if (nd1000 && (w != (res * 85 / 10 & ~3) || h < 1 || h > res * 11)) {
            fprintf(stderr, "ND scan requires full sensor width and at most 11 inches of height\n");
            rc = 2;
            goto close_device;
        }
        rc = do_scan(res, bpp, argv[5], NULL, w, h);
    } else if (!strcmp(argv[2], "duplex") && argc > 6) {
        int res = atoi(argv[3]), bpp = atoi(argv[4]);
        if (nd1000 && ((res != 150 && res != 200 && res != 300 && res != 600) ||
                       (bpp != 24 && bpp != 8))) {
            fprintf(stderr, "ND duplex supports 150, 200, 300 or 600 dpi in color or gray\n");
            rc = 2;
            goto close_device;
        }
        int w = res * 85 / 10 & ~3;
        int h = res * 11;
        rc = do_scan(res, bpp, argv[5], argv[6], w, h);
    } else if (!strcmp(argv[2], "program") && argc > 4) {
        /* Capture the set-params/calib/start register programs without
         * reading an image; combine with NEAT_NOPAPER=1 for no-paper runs. */
        int res = atoi(argv[3]), bpp = atoi(argv[4]);
        capture_only = 1;
        rc = do_scan(res, bpp, "/dev/null", NULL, res * 85 / 10 & ~3, res * 11);
    } else {
        fprintf(stderr, "bad command\n");
        rc = 2;
    }
close_device:
    cmd("close", 8, NULL, NULL, NULL, 0, 0);
    return rc;
}
