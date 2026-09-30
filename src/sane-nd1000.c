// SPDX-License-Identifier: GPL-2.0-or-later WITH SANE-exception
/* SANE backend "nd1000" for the Neat ND-1000 duplex CIS scanner (1f44:0050),
 * built on the native device core in src/nd1000.c. No vendor software is
 * needed at run time.
 *
 * Source selects the side(s): ADF Duplex (front then back), ADF Front, or
 * ADF Back. One physical pass images both sides; each side is returned as a
 * separate SANE page.
 */
#define _GNU_SOURCE
#include <sane/sane.h>

#include <errno.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "nd1000.h"

#define EXPORT __attribute__((visibility("default")))
#define MAX_HEIGHT_MM 279

enum { OPT_COUNT, OPT_MODE, OPT_RESOLUTION, OPT_SOURCE, NUM_OPTIONS };
enum { SRC_FRONT, SRC_BACK, SRC_DUPLEX };

struct nd_scanner {
    SANE_Option_Descriptor options[NUM_OPTIONS];
    SANE_Parameters params;
    struct nd1000 *dev;
    unsigned char *page;
    size_t length, offset;
    unsigned char *back;
    size_t back_length;
    int back_lines;
    int have_back;
    SANE_Word resolution;
    int source;
    int gray;
    int started;
};

static _Atomic int open_count;

static SANE_Device device = {"usb:1f44:0050", "Neat", "ND-1000 (duplex ADF)",
                             "sheetfed scanner"};
static const SANE_Device *devices[] = {&device, NULL};
static const SANE_Device *empty_devices[] = {NULL};
static const SANE_String_Const modes[] = {"Color", "Gray", NULL};
static const SANE_String_Const sources[] = {"ADF Front", "ADF Back", "ADF Duplex", NULL};
static const SANE_String_Const front_source[] = {"ADF Front", NULL};
static const SANE_Word resolutions[] = {4, 150, 200, 300, 600};

static void core_log(int level, const char *msg)
{
    if (level <= 1)
        fprintf(stderr, "[nd1000] %s\n", msg);
}

static void update_geometry(struct nd_scanner *s)
{
    /* The native core reports exact geometry per page in sane_start(); this
     * is only a pre-start estimate for sane_get_parameters(). */
    s->params.format = s->gray ? SANE_FRAME_GRAY : SANE_FRAME_RGB;
    s->params.last_frame = SANE_TRUE;
    s->params.depth = 8;
    s->params.pixels_per_line = (s->resolution * 85 / 10) & ~3;
    s->params.bytes_per_line = s->params.pixels_per_line * (s->gray ? 1 : 3);
    s->params.lines = -1;
}

static void update_source_constraint(struct nd_scanner *s)
{
    s->options[OPT_SOURCE].constraint.string_list =
        s->resolution == 300 ? sources : front_source;
}

static void init_options(struct nd_scanner *s)
{
    SANE_Option_Descriptor *o = s->options;
    memset(o, 0, sizeof(s->options));
    o[OPT_COUNT].name = "";
    o[OPT_COUNT].title = "Number of options";
    o[OPT_COUNT].desc = "Number of options available for this scanner.";
    o[OPT_COUNT].type = SANE_TYPE_INT;
    o[OPT_COUNT].size = sizeof(SANE_Word);
    o[OPT_COUNT].cap = SANE_CAP_SOFT_DETECT;
    o[OPT_MODE].name = "mode";
    o[OPT_MODE].title = "Scan mode";
    o[OPT_MODE].desc = "Colour scanning.";
    o[OPT_MODE].type = SANE_TYPE_STRING;
    o[OPT_MODE].size = 16;
    o[OPT_MODE].cap = SANE_CAP_SOFT_DETECT | SANE_CAP_SOFT_SELECT;
    o[OPT_MODE].constraint_type = SANE_CONSTRAINT_STRING_LIST;
    o[OPT_MODE].constraint.string_list = modes;
    o[OPT_RESOLUTION].name = "resolution";
    o[OPT_RESOLUTION].title = "Resolution";
    o[OPT_RESOLUTION].desc = "Scan resolution in dots per inch.";
    o[OPT_RESOLUTION].type = SANE_TYPE_INT;
    o[OPT_RESOLUTION].unit = SANE_UNIT_DPI;
    o[OPT_RESOLUTION].size = sizeof(SANE_Word);
    o[OPT_RESOLUTION].cap = SANE_CAP_SOFT_DETECT | SANE_CAP_SOFT_SELECT;
    o[OPT_RESOLUTION].constraint_type = SANE_CONSTRAINT_WORD_LIST;
    o[OPT_RESOLUTION].constraint.word_list = resolutions;
    o[OPT_SOURCE].name = "source";
    o[OPT_SOURCE].title = "Scan source";
    o[OPT_SOURCE].desc = "Document feeder side(s): front, back, or both.";
    o[OPT_SOURCE].type = SANE_TYPE_STRING;
    o[OPT_SOURCE].size = 16;
    o[OPT_SOURCE].cap = SANE_CAP_SOFT_DETECT | SANE_CAP_SOFT_SELECT;
    o[OPT_SOURCE].constraint_type = SANE_CONSTRAINT_STRING_LIST;
    s->resolution = 300;
    s->source = SRC_FRONT;
    update_source_constraint(s);
    update_geometry(s);
}

/* Convert an interleaved RGB buffer to 8-bit gray (Rec. 601 luma). */
static unsigned char *to_gray(const unsigned char *rgb, int pixels, int lines)
{
    unsigned char *g = malloc((size_t)pixels * lines);
    if (!g)
        return NULL;
    for (size_t i = 0, n = (size_t)pixels * lines; i < n; i++)
        g[i] = (77u * rgb[3 * i] + 150u * rgb[3 * i + 1] + 29u * rgb[3 * i + 2]) >> 8;
    return g;
}

/* Scan one sheet: program, drain the whole image FIFO (all sides share the
 * record stream), then decode the requested side(s) with the recovered
 * per-mode packing. */
static SANE_Status acquire(struct nd_scanner *s)
{
    struct nd1000_scan_info info;
    unsigned char *front = NULL, *back = NULL;
    uint8_t *raw = NULL;
    size_t rawlen = 0;
    int r, W, Hf = 0, Hb = 0;
    int chn = s->gray ? 1 : 3;

    r = nd1000_open(&s->dev, -1, -1);
    if (r)
        return r == ND1000_ERR_NODEV ? SANE_STATUS_ACCESS_DENIED : SANE_STATUS_IO_ERROR;
    r = nd1000_paper_present(s->dev);
    if (r <= 0) {
        nd1000_close(s->dev);
        s->dev = NULL;
        return r == 0 ? SANE_STATUS_NO_DOCS : SANE_STATUS_IO_ERROR;
    }
    nd1000_set_duplex(s->dev, s->source == SRC_DUPLEX);
    r = nd1000_start(s->dev, s->resolution, MAX_HEIGHT_MM, &info);
    if (r) {
        nd1000_close(s->dev);
        s->dev = NULL;
        return r == ND1000_ERR_NOPAPER ? SANE_STATUS_NO_DOCS : SANE_STATUS_IO_ERROR;
    }
    r = nd1000_read_all(s->dev, &raw, &rawlen);
    int stop = nd1000_finish(s->dev);
    nd1000_close(s->dev);
    s->dev = NULL;
    if (r == ND1000_OK && stop != ND1000_OK)
        r = stop;
    if (r != ND1000_OK && r != ND1000_EOF) {
        free(raw);
        return r == ND1000_ERR_NOPAPER ? SANE_STATUS_NO_DOCS : SANE_STATUS_IO_ERROR;
    }

    W = info.pixels;
    Hf = nd1000_decode_height(s->resolution, 0, rawlen);
    if (Hf > info.max_lines)
        Hf = info.max_lines;
    /* A partial FIFO stream must not masquerade as a successfully scanned
     * page. Both sides of one sheet must have comparable line counts. */
    if (Hf < s->resolution / 2) {
        free(raw);
        return SANE_STATUS_IO_ERROR;
    }
    if (s->source != SRC_BACK) {
        if (Hf > 0) {
            front = malloc((size_t)W * Hf * 3);
            if (front && (nd1000_decode_page(s->resolution, 0, raw, rawlen, front, W, Hf) ||
                          nd1000_realign_page(s->resolution, 0, front, W, Hf))) {
                free(front);
                front = NULL;
            }
        }
    }
    if (s->source != SRC_FRONT) {
        Hb = nd1000_decode_height(s->resolution, 1, rawlen);
        if (Hb > info.max_lines)
            Hb = info.max_lines;
        if (Hb < Hf / 2) {
            free(front); free(raw);
            return SANE_STATUS_IO_ERROR;
        }
        if (Hb > 0) {
            back = malloc((size_t)W * Hb * 3);
            if (back && (nd1000_decode_page(s->resolution, 1, raw, rawlen, back, W, Hb) ||
                         nd1000_realign_page(s->resolution, 1, back, W, Hb))) {
                free(back);
                back = NULL;
            }
        }
    }
    free(raw);
    if ((s->source != SRC_BACK && (!front || Hf <= 0)) ||
        (s->source != SRC_FRONT && (!back || Hb <= 0))) {
        free(front); free(back);
        return SANE_STATUS_IO_ERROR;
    }

    if (front)
        Hf = nd1000_trim_trailing_blank(front, W * 3, Hf);
    if (back)
        Hb = nd1000_trim_trailing_blank(back, W * 3, Hb);

    if (s->gray) {
        unsigned char *gf = front ? to_gray(front, W, Hf) : NULL;
        unsigned char *gb = back ? to_gray(back, W, Hb) : NULL;
        if ((front && !gf) || (back && !gb)) {
            free(gf); free(gb); free(front); free(back);
            return SANE_STATUS_NO_MEM;
        }
        free(front); free(back);
        front = gf; back = gb;
    }

    s->params.format = s->gray ? SANE_FRAME_GRAY : SANE_FRAME_RGB;
    s->params.depth = 8;
    s->params.last_frame = SANE_TRUE;
    s->params.pixels_per_line = W;
    s->params.bytes_per_line = W * chn;

    if (s->source == SRC_BACK) {
        free(front);
        s->page = back; s->length = (size_t)W * chn * Hb;
        s->params.lines = Hb;
    } else {
        s->page = front; s->length = (size_t)W * chn * Hf;
        s->params.lines = Hf;
        if (s->source == SRC_DUPLEX && back && Hb > 0) {
            s->back = back; s->back_length = (size_t)W * chn * Hb;
            s->back_lines = Hb; s->have_back = 1;
        } else {
            free(back);
        }
    }
    s->offset = 0;
    s->started = 1;
    return SANE_STATUS_GOOD;
}

EXPORT SANE_Status sane_nd1000_init(SANE_Int *version, SANE_Auth_Callback auth)
{
    (void)auth;
    nd1000_set_log(core_log);
    if (version)
        *version = SANE_VERSION_CODE(SANE_CURRENT_MAJOR, 0, 2);
    return SANE_STATUS_GOOD;
}
EXPORT void sane_nd1000_exit(void) {}

static int present(void)
{
    struct nd1000 *d = NULL;
    int r = nd1000_open(&d, -1, -1);
    if (r == 0) {
        nd1000_close(d);
        return 1;
    }
    return 0;
}

EXPORT SANE_Status sane_nd1000_get_devices(const SANE_Device ***list, SANE_Bool local_only)
{
    (void)local_only;
    *list = present() ? devices : empty_devices;
    return SANE_STATUS_GOOD;
}
EXPORT SANE_Status sane_nd1000_open(SANE_String_Const name, SANE_Handle *handle)
{
    struct nd_scanner *s;
    int expected = 0;
    if (name && *name && strcmp(name, device.name))
        return SANE_STATUS_INVAL;
    if (!atomic_compare_exchange_strong(&open_count, &expected, 1))
        return SANE_STATUS_DEVICE_BUSY;
    s = calloc(1, sizeof(*s));
    if (!s) {
        atomic_store(&open_count, 0);
        return SANE_STATUS_NO_MEM;
    }
    init_options(s);
    *handle = s;
    return SANE_STATUS_GOOD;
}
EXPORT void sane_nd1000_close(SANE_Handle handle)
{
    struct nd_scanner *s = handle;
    if (!s)
        return;
    if (s->dev) {
        nd1000_close(s->dev);
        s->dev = NULL;
    }
    free(s->page);
    free(s->back);
    free(s);
    atomic_store(&open_count, 0);
}
EXPORT const SANE_Option_Descriptor *sane_nd1000_get_option_descriptor(SANE_Handle handle, SANE_Int n)
{
    struct nd_scanner *s = handle;
    return n >= 0 && n < NUM_OPTIONS ? &s->options[n] : NULL;
}
EXPORT SANE_Status sane_nd1000_control_option(SANE_Handle handle, SANE_Int n, SANE_Action action,
                                                void *value, SANE_Int *info)
{
    struct nd_scanner *s = handle;
    if (info) *info = 0;
    if (n < 0 || n >= NUM_OPTIONS || !value || action == SANE_ACTION_SET_AUTO)
        return SANE_STATUS_INVAL;
    if (action == SANE_ACTION_GET_VALUE) {
        if (n == OPT_COUNT) *(SANE_Word *)value = NUM_OPTIONS;
        if (n == OPT_MODE) strcpy(value, s->gray ? "Gray" : "Color");
        if (n == OPT_RESOLUTION) *(SANE_Word *)value = s->resolution;
        if (n == OPT_SOURCE)
            strcpy(value, s->source == SRC_FRONT ? "ADF Front" :
                          s->source == SRC_BACK ? "ADF Back" : "ADF Duplex");
        return SANE_STATUS_GOOD;
    }
    if (action != SANE_ACTION_SET_VALUE || n == OPT_COUNT || s->started)
        return SANE_STATUS_INVAL;
    if (n == OPT_MODE) {
        int gray;
        if (!strcmp(value, "Color")) gray = 0;
        else if (!strcmp(value, "Gray")) gray = 1;
        else return SANE_STATUS_INVAL;
        if (gray != s->gray) {
            free(s->back); s->back = NULL; s->back_length = 0; s->back_lines = 0;
            s->have_back = 0;
            s->gray = gray;
            update_geometry(s);
            if (info) *info |= SANE_INFO_RELOAD_PARAMS;
        }
        return SANE_STATUS_GOOD;
    }
    if (n == OPT_SOURCE) {
        int newsrc;
        if (!strcmp(value, "ADF Front")) newsrc = SRC_FRONT;
        else if (!strcmp(value, "ADF Back")) newsrc = SRC_BACK;
        else if (!strcmp(value, "ADF Duplex")) newsrc = SRC_DUPLEX;
        else return SANE_STATUS_INVAL;
        if (newsrc != SRC_FRONT && s->resolution != 300)
            return SANE_STATUS_INVAL;
        if (newsrc != s->source) {
            free(s->back); s->back = NULL; s->back_length = 0; s->back_lines = 0;
            s->have_back = 0; s->source = newsrc;
        }
        return SANE_STATUS_GOOD;
    }
    for (int i = 1; i <= resolutions[0]; i++) {
        if (*(SANE_Word *)value == resolutions[i]) {
            if (s->source != SRC_FRONT && resolutions[i] != 300)
                return SANE_STATUS_INVAL;
            if (resolutions[i] != s->resolution) {
                free(s->back); s->back = NULL; s->back_length = 0; s->back_lines = 0;
                s->have_back = 0; s->resolution = resolutions[i];
                update_source_constraint(s);
                update_geometry(s);
                if (info) *info |= SANE_INFO_RELOAD_OPTIONS;
            }
            if (info) *info |= SANE_INFO_RELOAD_PARAMS;
            return SANE_STATUS_GOOD;
        }
    }
    return SANE_STATUS_INVAL;
}
EXPORT SANE_Status sane_nd1000_get_parameters(SANE_Handle handle, SANE_Parameters *params)
{
    *params = ((struct nd_scanner *)handle)->params;
    return SANE_STATUS_GOOD;
}
EXPORT SANE_Status sane_nd1000_start(SANE_Handle handle)
{
    struct nd_scanner *s = handle;
    if (s->source != SRC_FRONT && s->resolution != 300)
        return SANE_STATUS_UNSUPPORTED;
    free(s->page); s->page = NULL;
    s->length = s->offset = 0; s->started = 0; s->params.lines = -1;
    /* Serve a buffered back side from the previous duplex pass. */
    if (s->have_back) {
        s->page = s->back; s->length = s->back_length; s->params.lines = s->back_lines;
        s->back = NULL; s->back_length = 0; s->back_lines = 0; s->have_back = 0;
        s->started = 1;
        return SANE_STATUS_GOOD;
    }
    return acquire(s);
}
EXPORT SANE_Status sane_nd1000_read(SANE_Handle handle, SANE_Byte *data, SANE_Int max, SANE_Int *length)
{
    struct nd_scanner *s = handle;
    *length = 0;
    if (!s->started || s->offset == s->length) {
        s->started = 0;
        s->params.lines = -1;
        return SANE_STATUS_EOF;
    }
    if (!data || max <= 0)
        return SANE_STATUS_INVAL;
    size_t n = s->length - s->offset;
    if (n > (size_t)max)
        n = max;
    memcpy(data, s->page + s->offset, n);
    s->offset += n;
    *length = (SANE_Int)n;
    return SANE_STATUS_GOOD;
}
EXPORT void sane_nd1000_cancel(SANE_Handle handle)
{
    struct nd_scanner *s = handle;
    s->started = 0;
    s->have_back = 0;
    free(s->back); s->back = NULL; s->back_length = 0; s->back_lines = 0;
}
EXPORT SANE_Status sane_nd1000_set_io_mode(SANE_Handle handle, SANE_Bool nonblock)
{ (void)handle; return nonblock ? SANE_STATUS_UNSUPPORTED : SANE_STATUS_GOOD; }
EXPORT SANE_Status sane_nd1000_get_select_fd(SANE_Handle handle, SANE_Int *fd)
{ (void)handle; (void)fd; return SANE_STATUS_UNSUPPORTED; }

#define ALIAS(n) __attribute__((alias("sane_nd1000_" #n), visibility("default")))
SANE_Status sane_init(SANE_Int *, SANE_Auth_Callback) ALIAS(init);
void sane_exit(void) ALIAS(exit);
SANE_Status sane_get_devices(const SANE_Device ***, SANE_Bool) ALIAS(get_devices);
SANE_Status sane_open(SANE_String_Const, SANE_Handle *) ALIAS(open);
void sane_close(SANE_Handle) ALIAS(close);
const SANE_Option_Descriptor *sane_get_option_descriptor(SANE_Handle, SANE_Int) ALIAS(get_option_descriptor);
SANE_Status sane_control_option(SANE_Handle, SANE_Int, SANE_Action, void *, SANE_Int *) ALIAS(control_option);
SANE_Status sane_get_parameters(SANE_Handle, SANE_Parameters *) ALIAS(get_parameters);
SANE_Status sane_start(SANE_Handle) ALIAS(start);
SANE_Status sane_read(SANE_Handle, SANE_Byte *, SANE_Int, SANE_Int *) ALIAS(read);
void sane_cancel(SANE_Handle) ALIAS(cancel);
SANE_Status sane_set_io_mode(SANE_Handle, SANE_Bool) ALIAS(set_io_mode);
SANE_Status sane_get_select_fd(SANE_Handle, SANE_Int *) ALIAS(get_select_fd);
