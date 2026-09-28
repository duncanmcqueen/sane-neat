// SPDX-License-Identifier: GPL-2.0-or-later WITH SANE-exception
/* ND-1000 SANE bridge for colour ADF scanning.
 * Neat's DLL is loaded by the separate Linux PE harness, never linked here.
 * This is a bridge while the ND calibration and image protocol are ported.
 */
#define _GNU_SOURCE
#include <sane/sane.h>
#include <libusb-1.0/libusb.h>
#include <errno.h>
#include <fcntl.h>
#include <ftw.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#define EXPORT __attribute__((visibility("default")))
#define CHANNELS 3
#define MAX_DPI 600
#define MAX_HEIGHT_INCHES 11
#define DEFAULT_CAP "/usr/local/libexec/neatcap"
#define DEFAULT_DLL "/usr/local/lib/nd1000/neatadfscanner_x64.dll"

enum { OPT_COUNT, OPT_MODE, OPT_RESOLUTION, OPT_SOURCE, NUM_OPTIONS };

struct nd_scanner {
    SANE_Option_Descriptor options[NUM_OPTIONS];
    SANE_Parameters params;
    SANE_Word resolution;
    unsigned char *page;
    size_t length, offset;
    int started;
    _Atomic int cancelled;
    _Atomic pid_t child_pid;
    /* ND-1000 duplex: one pass returns both sides. The second side is
     * buffered here and served by the following sane_start(). */
    unsigned char *back;
    size_t back_length;
    int back_lines;
    int have_back;
    int source;
};

enum { SRC_FRONT, SRC_BACK, SRC_DUPLEX };

static _Atomic int open_count;

static SANE_Device device = {"usb:1f44:0050", "Neat", "ND-1000 (duplex ADF)",
                             "sheetfed scanner"};
static const SANE_Device *devices[] = {&device, NULL};
static const SANE_Device *empty_devices[] = {NULL};
static const SANE_String_Const modes[] = {"Color", NULL};
static const SANE_String_Const sources[] = {"ADF Front", "ADF Back", "ADF Duplex", NULL};
static const SANE_Word resolutions[] = {4, 150, 200, 300, 600};

static int scan_width(int dpi) { return (dpi * 85 / 10) & ~3; }

static void update_geometry(struct nd_scanner *s)
{
    s->params.pixels_per_line = scan_width(s->resolution);
    s->params.bytes_per_line = s->params.pixels_per_line * CHANNELS;
    s->params.lines = -1;
}

static const char *setting(const char *name, const char *fallback)
{
    const char *value = getenv(name);
    return value && *value ? value : fallback;
}

static int present(void)
{
    libusb_context *ctx = NULL;
    libusb_device **list = NULL;
    ssize_t count;
    int match = 0;
    if (libusb_init(&ctx))
        return 0;
    count = libusb_get_device_list(ctx, &list);
    if (count >= 0) {
        for (ssize_t i = 0; i < count; i++) {
            struct libusb_device_descriptor d;
            if (!libusb_get_device_descriptor(list[i], &d) &&
                d.idVendor == 0x1f44 && d.idProduct == 0x0050) {
                match = 1;
                break;
            }
        }
        libusb_free_device_list(list, 1);
    }
    libusb_exit(ctx);
    return match;
}

static int remove_entry(const char *path, const struct stat *st, int type, struct FTW *info)
{
    (void)st; (void)info;
    return type == FTW_DP ? rmdir(path) : unlink(path);
}

/* Run the harness with a private working directory. Child stderr is kept for
 * diagnostics; traces are suppressed to avoid logging document contents. */
static int run(struct nd_scanner *s, const char *dir, const char *action,
               const char *output, const char *output_back, char *reply, size_t size)
{
    int pipefd[2];
    pid_t pid;
    int status;
    const char *cap = setting("NEAT_ND_CAP", DEFAULT_CAP);
    const char *dll = setting("NEAT_ND_DLL", DEFAULT_DLL);
    if (access(cap, X_OK) || access(dll, R_OK) || pipe(pipefd))
        return -1;
    pid = fork();
    if (pid < 0) {
        close(pipefd[0]); close(pipefd[1]);
        return -1;
    }
    if (!pid) {
        char dpi[16];
        close(pipefd[0]);
        if (dup2(pipefd[1], STDOUT_FILENO) < 0 || chdir(dir) != 0)
            _exit(127);
        close(pipefd[1]);
        setenv("NEAT_USB_PID", "0050", 1);
        setenv("NEAT_TRACE", "/dev/null", 1);
        setenv("NEAT_WINROOT", dir, 1);
        alarm(output ? (s->resolution >= MAX_DPI ? 180 : 90) : 45);
        snprintf(dpi, sizeof(dpi), "%d", s->resolution);
        if (output_back)
            execl(cap, cap, dll, action, dpi, "24", output, output_back, (char *)NULL);
        else if (output)
            execl(cap, cap, dll, action, dpi, "24", output, (char *)NULL);
        else
            execl(cap, cap, dll, action, (char *)NULL);
        _exit(127);
    }
    close(pipefd[1]);
    atomic_store(&s->child_pid, pid);
    if (atomic_load(&s->cancelled))
        kill(pid, SIGTERM);
    size_t used = 0;
    char buffer[256];
    ssize_t n;
    int read_error = 0;
    while ((n = read(pipefd[0], buffer, sizeof(buffer))) != 0) {
        if (n < 0) {
            if (errno == EINTR) continue;
            kill(pid, SIGTERM);
            read_error = 1;
            break;
        }
        if (reply && size && used < size - 1) {
            size_t take = (size_t)n < size - 1 - used ? (size_t)n : size - 1 - used;
            memcpy(reply + used, buffer, take);
            used += take;
        }
    }
    close(pipefd[0]);
    if (reply && size)
        reply[used] = 0;
    pid_t reaped;
    do { reaped = waitpid(pid, &status, 0); } while (reaped < 0 && errno == EINTR);
    atomic_store(&s->child_pid, 0);
    if (reaped != pid || read_error || atomic_load(&s->cancelled))
        return -1;
    return WIFEXITED(status) && WEXITSTATUS(status) == 0 ? 0 : -1;
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
    o[OPT_SOURCE].constraint.string_list = sources;
    s->params.format = SANE_FRAME_RGB;
    s->params.last_frame = SANE_TRUE;
    s->params.depth = 8;
    s->resolution = 150;
    s->source = SRC_DUPLEX;
    update_geometry(s);
}

EXPORT SANE_Status sane_nd1000_init(SANE_Int *version, SANE_Auth_Callback auth)
{
    (void)auth;
    if (version)
        *version = SANE_VERSION_CODE(SANE_CURRENT_MAJOR, 0, 1);
    return SANE_STATUS_GOOD;
}
EXPORT void sane_nd1000_exit(void) {}
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
    if (!present())
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
    if (s) {
        free(s->page);
        free(s->back);
        free(s);
        atomic_store(&open_count, 0);
    }
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
        if (n == OPT_MODE) strcpy(value, "Color");
        if (n == OPT_RESOLUTION) *(SANE_Word *)value = s->resolution;
        if (n == OPT_SOURCE)
            strcpy(value, s->source == SRC_FRONT ? "ADF Front" :
                          s->source == SRC_BACK ? "ADF Back" : "ADF Duplex");
        return SANE_STATUS_GOOD;
    }
    if (action != SANE_ACTION_SET_VALUE || n == OPT_COUNT || s->started)
        return SANE_STATUS_INVAL;
    if (n == OPT_MODE) return strcmp(value, "Color") ? SANE_STATUS_INVAL : SANE_STATUS_GOOD;
    if (n == OPT_SOURCE) {
        int new_source;
        if (!strcmp(value, "ADF Front")) new_source = SRC_FRONT;
        else if (!strcmp(value, "ADF Back")) new_source = SRC_BACK;
        else if (!strcmp(value, "ADF Duplex")) new_source = SRC_DUPLEX;
        else return SANE_STATUS_INVAL;
        /* A no-op SET (between the two pages of one sheet) must keep the
         * buffered back side; only a real change invalidates it. */
        if (new_source != s->source) {
            free(s->back); s->back = NULL; s->back_length = 0; s->back_lines = 0;
            s->have_back = 0;
            s->source = new_source;
        }
        return SANE_STATUS_GOOD;
    }
    for (int i = 1; i <= resolutions[0]; i++) {
        if (*(SANE_Word *)value == resolutions[i]) {
            if (resolutions[i] != s->resolution) {
                /* Geometry change invalidates a buffered duplex back side. */
                free(s->back); s->back = NULL; s->back_length = 0; s->back_lines = 0;
                s->have_back = 0;
                s->resolution = resolutions[i];
                update_geometry(s);
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
/* Load and validate an 8-bit RGB PPM produced by the harness. */
static int load_ppm(const char *path, int expected_width, int max_lines,
                    unsigned char **data, size_t *len, int *lines)
{
    FILE *file = fopen(path, "rb");
    struct stat st;
    int width, n_lines, depth, c;
    if (!file)
        return -1;
    if (fscanf(file, "P6 %d %d %d", &width, &n_lines, &depth) != 3 ||
        width != expected_width || n_lines < 1 || n_lines > max_lines || depth != 255 ||
        (c = fgetc(file)) == EOF || c != '\n' || fstat(fileno(file), &st) ||
        st.st_size != ftell(file) + (long)expected_width * CHANNELS * n_lines) {
        fclose(file);
        return -1;
    }
    size_t n = (size_t)expected_width * CHANNELS * n_lines;
    unsigned char *buf = malloc(n);
    if (!buf || fread(buf, 1, n, file) != n) {
        free(buf);
        fclose(file);
        return -1;
    }
    fclose(file);
    *data = buf; *len = n; *lines = n_lines;
    return 0;
}

EXPORT SANE_Status sane_nd1000_start(SANE_Handle handle)
{
    struct nd_scanner *s = handle;
    char dir[] = "/tmp/sane-nd1000-XXXXXX";
    char output[128], backpath[128], reply[256];
    const int expected_width = scan_width(s->resolution);
    const int max_lines = s->resolution * MAX_HEIGHT_INCHES;
    SANE_Status result = SANE_STATUS_IO_ERROR;
    atomic_store(&s->cancelled, 0);

    /* The second side of the previous duplex sheet is already buffered. */
    if (s->have_back) {
        free(s->page);
        s->page = s->back;
        s->length = s->back_length;
        s->params.lines = s->back_lines;
        s->back = NULL; s->back_length = 0; s->back_lines = 0; s->have_back = 0;
        s->offset = 0; s->started = 1;
        return SANE_STATUS_GOOD;
    }

    free(s->page); s->page = NULL;
    s->length = s->offset = 0; s->started = 0; s->params.lines = -1;
    if (!mkdtemp(dir)) return SANE_STATUS_IO_ERROR;
    snprintf(output, sizeof(output), "%s/page.ppm", dir);
    snprintf(backpath, sizeof(backpath), "%s/back.ppm", dir);

    if (run(s, dir, "status", NULL, NULL, reply, sizeof(reply))) goto done;
    if (strstr(reply, "paper=0")) { result = SANE_STATUS_NO_DOCS; goto done; }
    if (!strstr(reply, "paper=1")) goto done;

    /* The ND-1000 images both sides in one pass, so always capture duplex
     * and then keep whichever side(s) the selected source needs. */
    {
        unsigned char *front = NULL, *back = NULL;
        size_t front_len = 0, back_len = 0;
        int front_lines = 0, back_lines = 0;
        int front_ok, back_ok;
        if (run(s, dir, "duplex", output, backpath, NULL, 0)) goto done;
        front_ok = load_ppm(output, expected_width, max_lines, &front, &front_len, &front_lines) == 0;
        back_ok = load_ppm(backpath, expected_width, max_lines, &back, &back_len, &back_lines) == 0;
        if (s->source == SRC_BACK) {
            if (!back_ok) { free(front); goto done; }
            free(front);
            s->page = back; s->length = back_len; s->params.lines = back_lines;
        } else {
            if (!front_ok) { free(back); goto done; }
            s->page = front; s->length = front_len; s->params.lines = front_lines;
            if (s->source == SRC_DUPLEX && back_ok) {
                s->back = back; s->back_length = back_len; s->back_lines = back_lines;
                s->have_back = 1;
            } else {
                free(back);
            }
        }
    }
    s->offset = 0;
    s->started = 1;
    result = SANE_STATUS_GOOD;
done:
    nftw(dir, remove_entry, 32, FTW_DEPTH | FTW_PHYS);
    if (atomic_load(&s->cancelled)) result = SANE_STATUS_CANCELLED;
    if (result != SANE_STATUS_GOOD) {
        free(s->page); s->page = NULL; s->length = 0;
        s->started = 0; s->params.lines = -1;
    }
    return result;
}
EXPORT SANE_Status sane_nd1000_read(SANE_Handle handle, SANE_Byte *data, SANE_Int max, SANE_Int *length)
{
    struct nd_scanner *s = handle;
    *length = 0;
    if (atomic_load(&s->cancelled)) return SANE_STATUS_CANCELLED;
    if (!s->started || s->offset == s->length) {
        s->started = 0;
        s->params.lines = -1;
        return SANE_STATUS_EOF;
    }
    if (!data || max <= 0) return SANE_STATUS_INVAL;
    size_t n = s->length - s->offset;
    if (n > (size_t)max) n = max;
    memcpy(data, s->page + s->offset, n);
    s->offset += n;
    *length = (SANE_Int)n;
    return SANE_STATUS_GOOD;
}
EXPORT void sane_nd1000_cancel(SANE_Handle handle)
{
    struct nd_scanner *s = handle;
    atomic_store(&s->cancelled, 1);
    pid_t pid = atomic_load(&s->child_pid);
    if (pid > 0) kill(pid, SIGTERM);
    s->started = 0;
    free(s->back); s->back = NULL; s->back_length = 0; s->back_lines = 0;
    s->have_back = 0;
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
