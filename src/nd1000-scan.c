// SPDX-License-Identifier: GPL-2.0-or-later WITH SANE-exception
/* Native ND-1000 scan utility: drives src/nd1000.c directly (no vendor DLL)
 * and writes PNM files. Used to validate the native core against real pages.
 *
 *   nd1000-scan DPI FRONT.pnm [BACK.pnm]
 */
#include "nd1000.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void logcb(int level, const char *msg)
{
    if (level <= 2)
        fprintf(stderr, "[%d] %s\n", level, msg);
}

static int write_pnm(const char *path, const uint8_t *buf, int width, int lines, int color)
{
    FILE *f = fopen(path, "wb");
    if (!f) {
        perror(path);
        return -1;
    }
    fprintf(f, color ? "P6\n%d %d\n255\n" : "P5\n%d %d\n255\n", width, lines);
    size_t n = (size_t)width * (color ? 3 : 1) * lines;
    int written = fwrite(buf, 1, n, f) == n;
    if (fclose(f) != 0)
        written = 0;
    if (!written) {
        fprintf(stderr, "write error on %s\n", path);
        return -1;
    }
    fprintf(stderr, "wrote %s: %dx%d %s\n", path, width, lines, color ? "RGB" : "gray");
    return 0;
}

int main(int argc, char **argv)
{
    struct nd1000 *d = NULL;
    struct nd1000_scan_info info;
    uint8_t *raw = NULL;
    uint8_t *front = NULL, *back = NULL;
    size_t rawlen = 0;
    int front_lines, back_lines = 0;
    int r;

    if (argc != 3 && argc != 4) {
        fprintf(stderr, "usage: %s DPI FRONT.pnm [BACK.pnm]\n", argv[0]);
        return 2;
    }
    int dpi = atoi(argv[1]);
    int duplex = argc > 3;
    int max_mm = getenv("ND1000_MAX_MM") ? atoi(getenv("ND1000_MAX_MM")) : 279;
    if ((dpi != 150 && dpi != 200 && dpi != 300 && dpi != 600) ||
        max_mm <= 0 || max_mm > 900 ||
        (duplex && nd1000_decode_height(dpi, 1, 0) < 0)) {
        fprintf(stderr, "DPI must be 150/200/300/600, height 1..900 mm; duplex needs 300 dpi\n");
        return 2;
    }

    nd1000_set_log(logcb);
    if ((r = nd1000_open(&d, -1, -1))) {
        fprintf(stderr, "open: %s\n", nd1000_strerror(r));
        return 1;
    }
    nd1000_set_duplex(d, duplex);
    fprintf(stderr, "serial %s\n", nd1000_serial(d));
    r = nd1000_paper_present(d);
    if (r <= 0) {
        fprintf(stderr, "feeder: %s\n", r == 0 ? "out of documents" : nd1000_strerror(r));
        nd1000_close(d);
        return 1;
    }
    if ((r = nd1000_start(d, dpi, max_mm, &info))) {
        fprintf(stderr, "start: %s\n", nd1000_strerror(r));
        nd1000_close(d);
        return 1;
    }
    r = nd1000_read_all(d, &raw, &rawlen);
    int stop = nd1000_finish(d);
    nd1000_close(d);
    if (r != ND1000_OK || stop != ND1000_OK) {
        fprintf(stderr, "scan failed: %s\n", nd1000_strerror(r != ND1000_OK ? r : stop));
        free(raw);
        return 1;
    }

    int front_stream = nd1000_decode_height(dpi, 0, rawlen);
    int back_stream = duplex ? nd1000_decode_height(dpi, 1, rawlen) : 0;
    /* Bound the result to the requested height, but test completeness against
     * the uncapped stream height: info.max_lines may be small on purpose. */
    if (front_stream < info.max_lines || (duplex && back_stream < front_stream / 2)) {
        fprintf(stderr, "incomplete page in the raw stream\n");
        free(raw);
        return 1;
    }
    front_lines = front_stream > info.max_lines ? info.max_lines : front_stream;
    back_lines = back_stream > info.max_lines ? info.max_lines : back_stream;

    front = malloc((size_t)info.pixels * 3 * front_lines);
    back = duplex ? malloc((size_t)info.pixels * 3 * back_lines) : NULL;
    if (!front || (duplex && !back) ||
        nd1000_decode_page(dpi, 0, raw, rawlen, front, info.pixels, front_lines) ||
        nd1000_realign_page(dpi, 0, front, info.pixels, front_lines) ||
        (duplex && (nd1000_decode_page(dpi, 1, raw, rawlen, back, info.pixels, back_lines) ||
                    nd1000_realign_page(dpi, 1, back, info.pixels, back_lines)))) {
        fprintf(stderr, "out of memory or unsupported image packing\n");
        free(raw); free(front); free(back);
        return 1;
    }
    free(raw);
    front_lines = nd1000_trim_trailing_blank(front, info.pixels * 3, front_lines);
    if (duplex)
        back_lines = nd1000_trim_trailing_blank(back, info.pixels * 3, back_lines);
    int rc = write_pnm(argv[2], front, info.pixels, front_lines, 1);
    if (duplex)
        rc |= write_pnm(argv[3], back, info.pixels, back_lines, 1);
    free(front);
    free(back);
    return rc ? 1 : 0;
}
