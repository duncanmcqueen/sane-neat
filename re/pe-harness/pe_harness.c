// SPDX-License-Identifier: GPL-2.0-or-later WITH SANE-exception
// Copyright (C) 2026 Evan McClain
/*
 * pe_harness: load Neat's 64-bit Windows scanner DLL (neatmobilescanner_x64.dll)
 * into a Linux process, forward the usbscan.sys calls it makes to libusb, and
 * log every USB transfer. Used only to capture the vendor driver's protocol so
 * a native driver can be written from the trace.
 *
 * The DLL is statically linked against the MSVC CRT; the only things it needs
 * from Windows are ~95 kernel32/user32/advapi32/shell32/shlwapi imports, which
 * are stubbed here with just enough behaviour for a single-threaded caller.
 */
#define _GNU_SOURCE
#include <asm/prctl.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <libusb-1.0/libusb.h>
#include <malloc.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#include "pe_harness.h"

#define WINAPI __attribute__((ms_abi))

typedef uint32_t DWORD;
typedef int32_t BOOL;
typedef void *HANDLE;
#define INVALID_HANDLE_VALUE ((HANDLE)(intptr_t)-1)

/* ------------------------------------------------------------------------ */
/* Logging                                                                   */

FILE *trace_fp;
int trace_bulk_in_full; /* dump every bulk-in byte (otherwise just a prefix) */
static int bulk_in_seq;
const char *bulk_dump_dir;
static DWORD last_error;

static void hexdump_line(FILE *fp, const uint8_t *p, size_t n, size_t max)
{
    size_t i;
    for (i = 0; i < n && i < max; i++)
        fprintf(fp, "%02x", p[i]);
    if (n > max)
        fprintf(fp, "...(+%zu)", n - max);
}

void trace(const char *fmt, ...)
{
    va_list ap;
    if (!trace_fp)
        return;
    va_start(ap, fmt);
    vfprintf(trace_fp, fmt, ap);
    va_end(ap);
    fflush(trace_fp);
}

/* ------------------------------------------------------------------------ */
/* USB                                                                       */

static libusb_context *usb_ctx;
static libusb_device_handle *usb_dev;
static uint16_t usb_pid = 0x0001;
#define FAKE_USB_HANDLE ((HANDLE)(intptr_t)0x5c5c0001)

int pe_set_usb_product(uint16_t pid)
{
    if (usb_dev || (pid != 0x0001 && pid != 0x0050))
        return 0;
    usb_pid = pid;
    return 1;
}

/* Fail before loading the vendor DLL when USB is not accessible. Otherwise
 * the DLL retries USBSCAN0 for a long time and hides the real problem. */
int pe_usb_accessible(void)
{
    libusb_context *ctx = NULL;
    libusb_device **list = NULL;
    ssize_t count;
    int rc = 0;
    if (libusb_init(&ctx))
        return 0;
    count = libusb_get_device_list(ctx, &list);
    if (count < 0) {
        libusb_exit(ctx);
        return 0;
    }
    for (ssize_t i = 0; i < count; i++) {
        struct libusb_device_descriptor desc;
        libusb_device_handle *h = NULL;
        if (libusb_get_device_descriptor(list[i], &desc) ||
            desc.idVendor != 0x1f44 || desc.idProduct != usb_pid)
            continue;
        int err = libusb_open(list[i], &h);
        if (err)
            fprintf(stderr, "harness: 1f44:%04x: %s (check USB ACL)\n", usb_pid,
                    libusb_error_name(err));
        else {
            libusb_set_auto_detach_kernel_driver(h, 1);
            err = libusb_claim_interface(h, 0);
            if (err)
                fprintf(stderr, "harness: cannot claim interface 0: %s\n", libusb_error_name(err));
            else {
                libusb_release_interface(h, 0);
                rc = 1;
            }
            libusb_close(h);
        }
        break;
    }
    if (!rc)
        fprintf(stderr, "harness: 1f44:%04x is unavailable\n", usb_pid);
    libusb_free_device_list(list, 1);
    libusb_exit(ctx);
    return rc;
}

static int usb_open(void)
{
    if (usb_dev)
        return 1;
    if (libusb_init(&usb_ctx) != 0)
        return 0;
    usb_dev = libusb_open_device_with_vid_pid(usb_ctx, 0x1f44, usb_pid);
    if (!usb_dev) {
        fprintf(stderr, "harness: cannot open 1f44:%04x (check udev permissions)\n", usb_pid);
        return 0;
    }
    libusb_set_auto_detach_kernel_driver(usb_dev, 1);
    if (libusb_claim_interface(usb_dev, 0) != 0) {
        fprintf(stderr, "harness: cannot claim interface 0\n");
        libusb_close(usb_dev);
        usb_dev = NULL;
        return 0;
    }
    return 1;
}

/* usbscan.sys IO_BLOCK (x64 layout) */
struct io_block {
    uint32_t offset;
    uint32_t length;
    uint8_t *data;
    uint32_t index;
};

#define IOCTL_READ_REGISTERS        0x8000200c
#define IOCTL_WRITE_REGISTERS       0x80002010
#define IOCTL_GET_CHANNEL_ALIGN     0x80002014
#define IOCTL_GET_DEVICE_DESCRIPTOR 0x80002018
#define IOCTL_RESET_PIPE            0x8000201c
#define IOCTL_WAIT_ON_DEVICE_EVENT  0x80002008
#define IOCTL_CANCEL_IO             0x80002004

static BOOL usb_ioctl(DWORD code, void *in, DWORD in_len, void *out, DWORD out_len, DWORD *ret_len)
{
    struct io_block *io = in;
    int r;
    uint8_t req;

    if (ret_len)
        *ret_len = 0;
    switch (code) {
    case IOCTL_READ_REGISTERS:
        req = io->length > 1 ? 0x04 : 0x0c;
        r = libusb_control_transfer(usb_dev, 0xc0, req, io->offset, io->index, out, io->length, 5000);
        trace("CI %02x %04x %04x %u -> ", req, io->offset, io->index, io->length);
        if (r < 0) {
            trace("ERR %s\n", libusb_error_name(r));
            return 0;
        }
        hexdump_line(trace_fp, out, r, 4096);
        trace("\n");
        if (ret_len)
            *ret_len = r;
        return 1;
    case IOCTL_WRITE_REGISTERS:
        req = io->length > 1 ? 0x04 : 0x0c;
        trace("CO %02x %04x %04x %u ", req, io->offset, io->index, io->length);
        hexdump_line(trace_fp, io->data, io->length, 4096);
        r = libusb_control_transfer(usb_dev, 0x40, req, io->offset, io->index, io->data, io->length, 5000);
        if (r < 0) {
            trace(" ERR %s\n", libusb_error_name(r));
            return 0;
        }
        trace("\n");
        return 1;
    case IOCTL_GET_DEVICE_DESCRIPTOR: {
        struct libusb_device_descriptor desc;
        uint16_t *d = out;
        if (out_len < 8 || libusb_get_device_descriptor(libusb_get_device(usb_dev), &desc))
            return 0;
        d[0] = desc.idVendor;
        d[1] = desc.idProduct;
        /* Field 2: the NM-1000 driver only ever saw the original constant,
         * so keep it there; the ND-1000 driver wants the device's bcdDevice. */
        d[2] = usb_pid == 0x0001 ? 0x0602 : desc.bcdDevice;
        d[3] = 0x0409;
        if (ret_len)
            *ret_len = 8;
        trace("IOCTL GET_DEVICE_DESCRIPTOR %04x:%04x bcdDevice=%04x\n", d[0], d[1], d[2]);
        return 1;
    }
    case IOCTL_RESET_PIPE:
        trace("IOCTL RESET_PIPE %u\n", in ? *(uint32_t *)in : 0);
        libusb_clear_halt(usb_dev, 0x81);
        libusb_clear_halt(usb_dev, 0x02);
        return 1;
    case IOCTL_CANCEL_IO:
        trace("IOCTL CANCEL_IO\n");
        return 1;
    case IOCTL_WAIT_ON_DEVICE_EVENT: {
        int got = 0;
        r = libusb_interrupt_transfer(usb_dev, 0x83, out, out_len > 1 ? 1 : out_len, &got, 1000);
        trace("INT -> %d %s\n", got, r ? libusb_error_name(r) : "");
        if (ret_len)
            *ret_len = got;
        return r == 0;
    }
    default:
        trace("IOCTL unknown %08x in=%u out=%u\n", code, in_len, out_len);
        return 0;
    }
}

static BOOL usb_bulk_in(void *buf, DWORD len, DWORD *got)
{
    int n = 0;
    int r = libusb_bulk_transfer(usb_dev, 0x81, buf, len, &n, 60000);
    trace("BI %u -> %d ", len, n);
    if (r) {
        trace("ERR %s\n", libusb_error_name(r));
        *got = n;
        return n > 0;
    }
    hexdump_line(trace_fp, buf, n, trace_bulk_in_full ? (size_t)n : 64);
    if (bulk_dump_dir && n > 64) {
        char path[512];
        FILE *f;
        snprintf(path, sizeof(path), "%s/bi_%05d.bin", bulk_dump_dir, bulk_in_seq);
        f = fopen(path, "wb");
        if (f) {
            fwrite(buf, 1, n, f);
            fclose(f);
        }
        trace(" [%s]", path);
    }
    bulk_in_seq++;
    trace("\n");
    *got = n;
    return 1;
}

static BOOL usb_bulk_out(const void *buf, DWORD len, DWORD *put)
{
    int n = 0;
    int r = libusb_bulk_transfer(usb_dev, 0x02, (unsigned char *)buf, len, &n, 10000);
    trace("BO %u ", len);
    hexdump_line(trace_fp, buf, len, 1 << 20);
    if (r) {
        trace(" ERR %s\n", libusb_error_name(r));
        *put = n;
        return 0;
    }
    trace("\n");
    *put = n;
    return 1;
}

/* ------------------------------------------------------------------------ */
/* Handles: the USB device, host files, and dummy event/mutex objects        */

#define MAX_HANDLES 256
enum { H_FREE, H_FILE, H_EVENT, H_MUTEX, H_HEAP, H_FIND };
static struct {
    int type;
    int fd;
} handles[MAX_HANDLES];

static HANDLE new_handle(int type, int fd)
{
    for (int i = 16; i < MAX_HANDLES; i++)
        if (handles[i].type == H_FREE) {
            handles[i].type = type;
            handles[i].fd = fd;
            return (HANDLE)(intptr_t)(i * 4);
        }
    return INVALID_HANDLE_VALUE;
}

static int handle_index(HANDLE h)
{
    intptr_t v = (intptr_t)h;
    if (v <= 0 || v % 4 || v / 4 >= MAX_HANDLES)
        return -1;
    return v / 4;
}

/* Windows paths → a sandbox under $NEAT_WINROOT (default ./winroot). */
static const char *winroot(void)
{
    const char *r = getenv("NEAT_WINROOT");
    return r ? r : "./winroot";
}

static void map_path(const char *win, char *out, size_t n)
{
    const char *p = win;
    if (isalpha((unsigned char)p[0]) && p[1] == ':')
        p += 2;
    snprintf(out, n, "%s/%s", winroot(), p);
    for (char *q = out + strlen(winroot()); *q; q++)
        if (*q == '\\')
            *q = '/';
}

static void mkdirs_for(const char *path)
{
    char tmp[1024];
    snprintf(tmp, sizeof(tmp), "%s", path);
    for (char *q = tmp + 1; *q; q++)
        if (*q == '/') {
            *q = 0;
            mkdir(tmp, 0755);
            *q = '/';
        }
}

/* ------------------------------------------------------------------------ */
/* kernel32 & friends                                                         */

static WINAPI HANDLE k_CreateFileA(const char *name, DWORD access, DWORD share, void *sa, DWORD disp,
                                   DWORD flags, HANDLE tmpl)
{
    (void)share, (void)sa, (void)flags, (void)tmpl;
    trace("CreateFileA(%s, %08x, disp=%u)\n", name, access, disp);
    if (!strncmp(name, "\\\\.\\USBSCAN", 11)) {
        if (atoi(name + 11) != 0 || !usb_open()) {
            last_error = 2;
            return INVALID_HANDLE_VALUE;
        }
        return FAKE_USB_HANDLE;
    }
    char path[1024];
    int oflags = 0;
    map_path(name, path, sizeof(path));
    if ((access & 0xc0000000) == 0xc0000000)
        oflags = O_RDWR;
    else if (access & 0x40000000)
        oflags = O_WRONLY;
    else
        oflags = O_RDONLY;
    switch (disp) {
    case 1: oflags |= O_CREAT | O_EXCL; break;  /* CREATE_NEW */
    case 2: oflags |= O_CREAT | O_TRUNC; break; /* CREATE_ALWAYS */
    case 4: oflags |= O_CREAT; break;           /* OPEN_ALWAYS */
    case 5: oflags |= O_TRUNC; break;           /* TRUNCATE_EXISTING */
    }
    if (oflags & O_CREAT)
        mkdirs_for(path);
    int fd = open(path, oflags, 0644);
    if (fd < 0) {
        last_error = 2;
        return INVALID_HANDLE_VALUE;
    }
    return new_handle(H_FILE, fd);
}

/* OVERLAPPED: Internal, InternalHigh, Offset/Pointer, hEvent */
struct overlapped {
    uintptr_t internal;
    uintptr_t internal_high;
    uint32_t offset, offset_high;
    HANDLE event;
};

static WINAPI BOOL k_ReadFile(HANDLE h, void *buf, DWORD n, DWORD *got, struct overlapped *ov)
{
    DWORD g = 0;
    BOOL ok;
    if (h == FAKE_USB_HANDLE) {
        ok = usb_bulk_in(buf, n, &g);
    } else {
        int i = handle_index(h);
        ssize_t r = i >= 0 && handles[i].type == H_FILE ? read(handles[i].fd, buf, n) : -1;
        ok = r >= 0;
        g = r > 0 ? r : 0;
    }
    if (got)
        *got = g;
    if (ov)
        ov->internal_high = g;
    return ok;
}

static WINAPI BOOL k_WriteFile(HANDLE h, const void *buf, DWORD n, DWORD *put, struct overlapped *ov)
{
    DWORD p = 0;
    BOOL ok;
    if (h == FAKE_USB_HANDLE) {
        ok = usb_bulk_out(buf, n, &p);
    } else {
        int i = handle_index(h);
        ssize_t r = i >= 0 && handles[i].type == H_FILE ? write(handles[i].fd, buf, n) : -1;
        ok = r >= 0;
        p = r > 0 ? r : 0;
    }
    if (put)
        *put = p;
    if (ov)
        ov->internal_high = p;
    return ok;
}

static WINAPI BOOL k_DeviceIoControl(HANDLE h, DWORD code, void *in, DWORD in_len, void *out, DWORD out_len,
                                     DWORD *ret, struct overlapped *ov)
{
    DWORD r = 0;
    BOOL ok;
    if (h != FAKE_USB_HANDLE) {
        last_error = 6;
        return 0;
    }
    ok = usb_ioctl(code, in, in_len, out, out_len, &r);
    if (ret)
        *ret = r;
    if (ov)
        ov->internal_high = r;
    if (!ok)
        last_error = 31; /* ERROR_GEN_FAILURE */
    return ok;
}

static WINAPI BOOL k_GetOverlappedResult(HANDLE h, struct overlapped *ov, DWORD *n, BOOL wait)
{
    (void)h, (void)wait;
    if (n)
        *n = ov->internal_high;
    return 1;
}

static WINAPI BOOL k_CancelIo(HANDLE h) { (void)h; return 1; }
static WINAPI BOOL k_FlushFileBuffers(HANDLE h) { (void)h; return 1; }

static WINAPI BOOL k_CloseHandle(HANDLE h)
{
    int i;
    if (h == FAKE_USB_HANDLE) {
        trace("CloseHandle(usb)\n");
        return 1;
    }
    i = handle_index(h);
    if (i < 0 || handles[i].type == H_FREE)
        return 0;
    if (handles[i].type == H_FILE)
        close(handles[i].fd);
    handles[i].type = H_FREE;
    return 1;
}

static WINAPI HANDLE k_CreateEventA(void *sa, BOOL manual, BOOL initial, const char *name)
{
    (void)sa, (void)manual, (void)initial, (void)name;
    return new_handle(H_EVENT, -1);
}

static WINAPI HANDLE k_CreateMutexA(void *sa, BOOL owner, const char *name)
{
    (void)sa, (void)owner;
    trace("CreateMutexA(%s)\n", name ? name : "");
    return new_handle(H_MUTEX, -1);
}

static WINAPI BOOL k_ReleaseMutex(HANDLE h) { (void)h; return 1; }
static WINAPI DWORD k_WaitForSingleObject(HANDLE h, DWORD ms) { (void)h, (void)ms; return 0; }

static WINAPI void k_Sleep(DWORD ms)
{
    trace("Sleep %u\n", ms);
    usleep(ms * 1000u);
}

static WINAPI DWORD k_GetTickCount(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000u + ts.tv_nsec / 1000000u;
}

/* The ND-1000 DLL checks the Windows version during DllMain. Present Win 7. */
static WINAPI DWORD k_GetVersion(void) { return (7601u << 16) | (1u << 8) | 6u; }

static WINAPI DWORD k_GetLastError(void) { return last_error; }
static WINAPI void k_SetLastError(DWORD e) { last_error = e; }

static WINAPI DWORD k_GetFileSize(HANDLE h, DWORD *high)
{
    int i = handle_index(h);
    struct stat st;
    if (i < 0 || handles[i].type != H_FILE || fstat(handles[i].fd, &st))
        return 0xffffffff;
    if (high)
        *high = (uint64_t)st.st_size >> 32;
    return st.st_size;
}

static WINAPI DWORD k_SetFilePointer(HANDLE h, int32_t lo, int32_t *hi, DWORD method)
{
    int i = handle_index(h);
    off_t off = lo;
    if (hi)
        off = ((off_t)*hi << 32) | (uint32_t)lo;
    if (i < 0 || handles[i].type != H_FILE)
        return 0xffffffff;
    off = lseek(handles[i].fd, off, method == 0 ? SEEK_SET : method == 1 ? SEEK_CUR : SEEK_END);
    if (hi)
        *hi = off >> 32;
    return (DWORD)off;
}

static WINAPI BOOL k_SetEndOfFile(HANDLE h)
{
    int i = handle_index(h);
    if (i < 0 || handles[i].type != H_FILE)
        return 0;
    return ftruncate(handles[i].fd, lseek(handles[i].fd, 0, SEEK_CUR)) == 0;
}

static WINAPI BOOL k_DeleteFileA(const char *name)
{
    char path[1024];
    map_path(name, path, sizeof(path));
    trace("DeleteFileA(%s)\n", name);
    return unlink(path) == 0;
}

static WINAPI BOOL k_CreateDirectoryA(const char *name, void *sa)
{
    char path[1024];
    (void)sa;
    map_path(name, path, sizeof(path));
    mkdirs_for(path);
    return mkdir(path, 0755) == 0 || errno == EEXIST;
}

static WINAPI HANDLE k_FindFirstFileA(const char *name, void *data)
{
    (void)data;
    trace("FindFirstFileA(%s)\n", name);
    last_error = 2;
    return INVALID_HANDLE_VALUE;
}

static WINAPI BOOL s_PathFileExistsA(const char *name)
{
    char path[1024];
    map_path(name, path, sizeof(path));
    int r = access(path, F_OK) == 0;
    trace("PathFileExistsA(%s) = %d\n", name, r);
    return r;
}

static WINAPI BOOL s_SHGetSpecialFolderPathA(HANDLE hwnd, char *out, int csidl, BOOL create)
{
    (void)hwnd, (void)create;
    snprintf(out, 260, "C:\\special%d", csidl);
    trace("SHGetSpecialFolderPathA(%d)\n", csidl);
    return 1;
}

static WINAPI DWORD k_GetModuleFileNameA(HANDLE mod, char *out, DWORD n)
{
    (void)mod;
    if (!n || !out)
        return 0;
    snprintf(out, n, "%s", usb_pid == 0x0050
             ? "C:\\Windows\\twain_32\\Neat ADF Scanner\\NeatADFScanner32.dll"
             : "C:\\Windows\\twain_32\\Neat Mobile Scanner\\NeatMobileScanner32.dll");
    return strlen(out);
}

/* Config values the DLL asks for. Unless overridden, return the default so we
 * learn which keys (and defaults) exist. */
static WINAPI unsigned k_GetPrivateProfileIntA(const char *sect, const char *key, int def, const char *file)
{
    trace("GetPrivateProfileIntA([%s] %s, def=%d, %s)\n", sect, key, def, file ? file : "");
    return def;
}

/* Heap */
static WINAPI HANDLE k_HeapCreate(DWORD o, size_t i, size_t m) { (void)o, (void)i, (void)m; return (HANDLE)0x4ea90000; }
static WINAPI BOOL k_HeapDestroy(HANDLE h) { (void)h; return 1; }
static WINAPI HANDLE k_GetProcessHeap(void) { return (HANDLE)0x4ea90000; }
static WINAPI BOOL k_HeapSetInformation(HANDLE h, int c, void *i, size_t l) { (void)h, (void)c, (void)i, (void)l; return 1; }

/* Keep the requested size in a header so HeapSize is exact. */
static WINAPI void *k_HeapAlloc(HANDLE h, DWORD flags, size_t n)
{
    (void)h;
    size_t *p = (flags & 8) ? calloc(1, n + 16) : malloc(n + 16);
    if (!p)
        return NULL;
    p[0] = n;
    return p + 2;
}

static WINAPI BOOL k_HeapFree(HANDLE h, DWORD flags, void *p)
{
    (void)h, (void)flags;
    if (p)
        free((size_t *)p - 2);
    return 1;
}

static WINAPI size_t k_HeapSize(HANDLE h, DWORD flags, const void *p)
{
    (void)h, (void)flags;
    return ((const size_t *)p)[-2];
}

static WINAPI void *k_HeapReAlloc(HANDLE h, DWORD flags, void *p, size_t n)
{
    size_t old = ((size_t *)p)[-2];
    size_t *q = realloc((size_t *)p - 2, n + 16);
    (void)h;
    if (!q)
        return NULL;
    if ((flags & 8) && n > old)
        memset((uint8_t *)(q + 2) + old, 0, n - old);
    q[0] = n;
    return q + 2;
}

/* FLS: single thread, a flat slot array is enough. */
static void *fls_slots[128];
static int fls_next;
static WINAPI DWORD k_FlsAlloc(void *cb) { (void)cb; return fls_next < 128 ? (DWORD)fls_next++ : 0xffffffff; }
static WINAPI void *k_FlsGetValue(DWORD i) { return i < 128 ? fls_slots[i] : NULL; }
static WINAPI BOOL k_FlsSetValue(DWORD i, void *v) { if (i >= 128) return 0; fls_slots[i] = v; return 1; }
static WINAPI BOOL k_FlsFree(DWORD i) { (void)i; return 1; }

static WINAPI void *k_EncodePointer(void *p) { return p; }
static WINAPI void *k_DecodePointer(void *p) { return p; }

static WINAPI DWORD k_GetCurrentThreadId(void) { return 1000; }
static WINAPI DWORD k_GetCurrentProcessId(void) { return 999; }
static WINAPI HANDLE k_GetCurrentProcess(void) { return (HANDLE)(intptr_t)-1; }

static WINAPI void k_GetSystemTimeAsFileTime(uint64_t *ft)
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    *ft = (uint64_t)tv.tv_sec * 10000000ull + tv.tv_usec * 10ull + 116444736000000000ull;
}

static WINAPI BOOL k_QueryPerformanceCounter(int64_t *c)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    *c = ts.tv_sec * 1000000000ll + ts.tv_nsec;
    return 1;
}

static char cmdline[] = "neat.exe";
static WINAPI char *k_GetCommandLineA(void) { return cmdline; }

static uint16_t empty_envw[2];
static char empty_env[2];
static WINAPI uint16_t *k_GetEnvironmentStringsW(void) { return empty_envw; }
static WINAPI char *k_GetEnvironmentStrings(void) { return empty_env; }
static WINAPI BOOL k_FreeEnvironmentStrings(void *p) { (void)p; return 1; }

static WINAPI void k_GetStartupInfoA(void *si)
{
    memset(si, 0, 104);
    *(DWORD *)si = 104;
}
static WINAPI void k_GetStartupInfoW(void *si) { k_GetStartupInfoA(si); }

static WINAPI HANDLE k_GetStdHandle(DWORD n) { return (HANDLE)(intptr_t)(0x100 + (n & 0xff)); }
static WINAPI DWORD k_GetFileType(HANDLE h) { (void)h; return 2; /* FILE_TYPE_CHAR */ }
static WINAPI unsigned k_SetHandleCount(unsigned n) { return n; }
static WINAPI BOOL k_SetStdHandle(DWORD n, HANDLE h) { (void)n, (void)h; return 1; }

static WINAPI unsigned k_GetACP(void) { return 1252; }
static WINAPI unsigned k_GetOEMCP(void) { return 437; }
static WINAPI BOOL k_IsValidCodePage(unsigned cp) { (void)cp; return 1; }
static WINAPI unsigned k_GetConsoleCP(void) { return 437; }
static WINAPI unsigned k_GetConsoleOutputCP(void) { return 437; }
static WINAPI BOOL k_GetConsoleMode(HANDLE h, DWORD *m) { (void)h; if (m) *m = 0; return 0; }

static WINAPI BOOL k_WriteConsoleA(HANDLE h, const char *s, DWORD n, DWORD *w, void *r)
{
    (void)h, (void)r;
    fwrite(s, 1, n, stderr);
    if (w)
        *w = n;
    return 1;
}

static WINAPI BOOL k_WriteConsoleW(HANDLE h, const uint16_t *s, DWORD n, DWORD *w, void *r)
{
    (void)h, (void)r;
    for (DWORD i = 0; i < n; i++)
        fputc(s[i] < 128 ? s[i] : '?', stderr);
    if (w)
        *w = n;
    return 1;
}

struct cpinfo {
    unsigned max_char_size;
    uint8_t default_char[2];
    uint8_t lead_byte[12];
};

static WINAPI BOOL k_GetCPInfo(unsigned cp, struct cpinfo *ci)
{
    (void)cp;
    memset(ci, 0, sizeof(*ci));
    ci->max_char_size = 1;
    ci->default_char[0] = '?';
    return 1;
}

/* Latin-1 identity conversions are fine for the ASCII this DLL handles. */
static WINAPI int k_MultiByteToWideChar(unsigned cp, DWORD fl, const char *s, int n, uint16_t *d, int dn)
{
    (void)cp, (void)fl;
    if (n < 0)
        n = strlen(s) + 1;
    if (!dn)
        return n;
    int i;
    for (i = 0; i < n && i < dn; i++)
        d[i] = (uint8_t)s[i];
    return i;
}

static WINAPI int k_WideCharToMultiByte(unsigned cp, DWORD fl, const uint16_t *s, int n, char *d, int dn,
                                        const char *def, BOOL *used)
{
    (void)cp, (void)fl, (void)def;
    if (used)
        *used = 0;
    if (n < 0) {
        n = 0;
        while (s[n])
            n++;
        n++;
    }
    if (!dn)
        return n;
    int i;
    for (i = 0; i < n && i < dn; i++)
        d[i] = s[i] < 256 ? (char)s[i] : '?';
    return i;
}

static WINAPI int k_LCMapStringA(DWORD lcid, DWORD fl, const char *s, int n, char *d, int dn)
{
    (void)lcid;
    if (n < 0)
        n = strlen(s) + 1;
    if (!dn)
        return n;
    int i;
    for (i = 0; i < n && i < dn; i++)
        d[i] = (fl & 0x100) ? toupper((unsigned char)s[i]) : (fl & 0x200) ? tolower((unsigned char)s[i]) : s[i];
    return i;
}

static WINAPI int k_LCMapStringW(DWORD lcid, DWORD fl, const uint16_t *s, int n, uint16_t *d, int dn)
{
    (void)lcid;
    if (n < 0) {
        n = 0;
        while (s[n])
            n++;
        n++;
    }
    if (!dn)
        return n;
    int i;
    for (i = 0; i < n && i < dn; i++) {
        uint16_t c = s[i];
        if (c < 128)
            c = (fl & 0x100) ? toupper(c) : (fl & 0x200) ? tolower(c) : c;
        d[i] = c;
    }
    return i;
}

static uint16_t ctype1(int c)
{
    uint16_t t = 0;
    if (c >= 128)
        return 0;
    if (isupper(c)) t |= 0x001;
    if (islower(c)) t |= 0x002;
    if (isdigit(c)) t |= 0x004;
    if (isspace(c)) t |= 0x008;
    if (ispunct(c)) t |= 0x010;
    if (iscntrl(c)) t |= 0x020;
    if (c == ' ' || c == '\t') t |= 0x040;
    if (isxdigit(c)) t |= 0x080;
    if (isalpha(c)) t |= 0x100;
    return t;
}

static WINAPI BOOL k_GetStringTypeA(DWORD lcid, DWORD type, const char *s, int n, uint16_t *out)
{
    (void)lcid, (void)type;
    if (n < 0)
        n = strlen(s) + 1;
    for (int i = 0; i < n; i++)
        out[i] = ctype1((uint8_t)s[i]);
    return 1;
}

static WINAPI BOOL k_GetStringTypeW(DWORD type, const uint16_t *s, int n, uint16_t *out)
{
    (void)type;
    if (n < 0) {
        n = 0;
        while (s[n])
            n++;
        n++;
    }
    for (int i = 0; i < n; i++)
        out[i] = ctype1(s[i]);
    return 1;
}

static WINAPI int k_GetLocaleInfoA(DWORD lcid, DWORD type, char *d, int n) { (void)lcid, (void)type, (void)d, (void)n; return 0; }

static WINAPI BOOL k_InitializeCriticalSectionAndSpinCount(void *cs, DWORD n) { (void)cs, (void)n; return 1; }
static WINAPI void k_EnterCriticalSection(void *cs) { (void)cs; }
static WINAPI void k_LeaveCriticalSection(void *cs) { (void)cs; }
static WINAPI void k_DeleteCriticalSection(void *cs) { (void)cs; }

static WINAPI BOOL k_IsDebuggerPresent(void) { return 0; }
static WINAPI void *k_SetUnhandledExceptionFilter(void *f) { (void)f; return NULL; }

static WINAPI size_t k_VirtualQuery(const void *addr, void *mbi, size_t len)
{
    (void)addr;
    memset(mbi, 0, len);
    return 0;
}

static WINAPI void k_ExitProcess(unsigned code)
{
    fprintf(stderr, "harness: DLL called ExitProcess(%u)\n", code);
    exit(code);
}

static WINAPI BOOL k_TerminateProcess(HANDLE h, unsigned code)
{
    (void)h;
    fprintf(stderr, "harness: DLL called TerminateProcess(%u)\n", code);
    exit(code);
}

static WINAPI void k_RaiseException(DWORD code, DWORD flags, DWORD n, const uintptr_t *args)
{
    (void)flags, (void)n, (void)args;
    fprintf(stderr, "harness: DLL raised exception %08x (C++ throw?) — aborting\n", code);
    abort();
}

static WINAPI void *k_RtlPcToFileHeader(void *pc, void **base)
{
    (void)pc;
    *base = NULL;
    return NULL;
}

static WINAPI int u_wsprintfA(char *out, const char *fmt, ...)
{
    /* MS varargs: everything is in 8-byte slots; va_list from ms_abi works via __builtin_ms_va_list. */
    __builtin_ms_va_list ap;
    __builtin_ms_va_start(ap, fmt);
    /* Only %d/%u/%x/%s/%c/%02x style formats are used by this DLL. */
    char *o = out;
    for (const char *f = fmt; *f; f++) {
        if (*f != '%') {
            *o++ = *f;
            continue;
        }
        char spec[32];
        int k = 0;
        spec[k++] = '%';
        f++;
        while (*f && strchr("-+ #0123456789.l", *f) && k < 30)
            spec[k++] = *f++;
        if (*f == '%') {
            *o++ = '%';
            continue;
        }
        spec[k++] = *f;
        spec[k] = 0;
        uintptr_t v = __builtin_va_arg(ap, uintptr_t);
        if (*f == 's')
            o += sprintf(o, spec, (const char *)v);
        else if (*f == 'c')
            o += sprintf(o, spec, (int)v);
        else {
            /* strip 'l': wsprintf %ld is 32-bit */
            char s2[32];
            int j = 0;
            for (int i = 0; spec[i]; i++)
                if (spec[i] != 'l')
                    s2[j++] = spec[i];
            s2[j] = 0;
            o += sprintf(o, s2, (unsigned)v);
        }
    }
    *o = 0;
    __builtin_ms_va_end(ap);
    return o - out;
}

static WINAPI BOOL a_true4(void *a, void *b, void *c, void *d) { (void)a, (void)b, (void)c, (void)d; return 1; }

/* Module handles & GetProcAddress (the CRT looks up FlsAlloc & co this way) */
#define FAKE_KERNEL32 ((HANDLE)(intptr_t)0x7ff00000)
static WINAPI HANDLE k_GetModuleHandleW(const uint16_t *name)
{
    char n[64] = {0};
    for (int i = 0; name && name[i] && i < 63; i++)
        n[i] = tolower(name[i]);
    trace("GetModuleHandleW(%s)\n", n);
    if (!name)
        return (HANDLE)image_base();
    if (strstr(n, "kernel32"))
        return FAKE_KERNEL32;
    return NULL;
}

static WINAPI HANDLE k_LoadLibraryA(const char *name)
{
    trace("LoadLibraryA(%s)\n", name);
    return NULL;
}

static void *lookup_stub(const char *dll, const char *name);

static WINAPI void *k_GetProcAddress(HANDLE mod, const char *name)
{
    void *p = NULL;
    if (mod == FAKE_KERNEL32 && (uintptr_t)name > 0xffff)
        p = lookup_stub("kernel32.dll", name);
    trace("GetProcAddress(%s) = %p\n", (uintptr_t)name > 0xffff ? name : "#ord", p);
    return p;
}

/* ------------------------------------------------------------------------ */
/* Import table                                                              */

struct stub {
    const char *dll;
    const char *name;
    void *fn;
};

static const struct stub stubs[] = {
    {"kernel32.dll", "CloseHandle", k_CloseHandle},
    {"kernel32.dll", "CancelIo", k_CancelIo},
    {"kernel32.dll", "WaitForSingleObject", k_WaitForSingleObject},
    {"kernel32.dll", "GetLastError", k_GetLastError},
    {"kernel32.dll", "SetLastError", k_SetLastError},
    {"kernel32.dll", "DeviceIoControl", k_DeviceIoControl},
    {"kernel32.dll", "CreateEventA", k_CreateEventA},
    {"kernel32.dll", "GetTickCount", k_GetTickCount},
    {"kernel32.dll", "GetVersion", k_GetVersion},
    {"kernel32.dll", "GetOverlappedResult", k_GetOverlappedResult},
    {"kernel32.dll", "CreateFileA", k_CreateFileA},
    {"kernel32.dll", "ReadFile", k_ReadFile},
    {"kernel32.dll", "WriteFile", k_WriteFile},
    {"kernel32.dll", "Sleep", k_Sleep},
    {"kernel32.dll", "FlushFileBuffers", k_FlushFileBuffers},
    {"kernel32.dll", "CreateMutexA", k_CreateMutexA},
    {"kernel32.dll", "ReleaseMutex", k_ReleaseMutex},
    {"kernel32.dll", "GetFileSize", k_GetFileSize},
    {"kernel32.dll", "DeleteFileA", k_DeleteFileA},
    {"kernel32.dll", "FindFirstFileA", k_FindFirstFileA},
    {"kernel32.dll", "CreateDirectoryA", k_CreateDirectoryA},
    {"kernel32.dll", "GetModuleFileNameA", k_GetModuleFileNameA},
    {"kernel32.dll", "VirtualQuery", k_VirtualQuery},
    {"kernel32.dll", "GetPrivateProfileIntA", k_GetPrivateProfileIntA},
    {"kernel32.dll", "LoadLibraryA", k_LoadLibraryA},
    {"kernel32.dll", "SetEndOfFile", k_SetEndOfFile},
    {"kernel32.dll", "SetFilePointer", k_SetFilePointer},
    {"kernel32.dll", "GetProcessHeap", k_GetProcessHeap},
    {"kernel32.dll", "TerminateProcess", k_TerminateProcess},
    {"kernel32.dll", "ExitProcess", k_ExitProcess},
    {"kernel32.dll", "HeapAlloc", k_HeapAlloc},
    {"kernel32.dll", "HeapFree", k_HeapFree},
    {"kernel32.dll", "HeapReAlloc", k_HeapReAlloc},
    {"kernel32.dll", "HeapSize", k_HeapSize},
    {"kernel32.dll", "HeapCreate", k_HeapCreate},
    {"kernel32.dll", "HeapDestroy", k_HeapDestroy},
    {"kernel32.dll", "HeapSetInformation", k_HeapSetInformation},
    {"kernel32.dll", "GetCurrentThreadId", k_GetCurrentThreadId},
    {"kernel32.dll", "GetCurrentProcessId", k_GetCurrentProcessId},
    {"kernel32.dll", "GetCurrentProcess", k_GetCurrentProcess},
    {"kernel32.dll", "FlsAlloc", k_FlsAlloc},
    {"kernel32.dll", "FlsGetValue", k_FlsGetValue},
    {"kernel32.dll", "FlsSetValue", k_FlsSetValue},
    {"kernel32.dll", "FlsFree", k_FlsFree},
    {"kernel32.dll", "EncodePointer", k_EncodePointer},
    {"kernel32.dll", "DecodePointer", k_DecodePointer},
    {"kernel32.dll", "GetCommandLineA", k_GetCommandLineA},
    {"kernel32.dll", "GetCPInfo", k_GetCPInfo},
    {"kernel32.dll", "GetACP", k_GetACP},
    {"kernel32.dll", "GetOEMCP", k_GetOEMCP},
    {"kernel32.dll", "IsValidCodePage", k_IsValidCodePage},
    {"kernel32.dll", "UnhandledExceptionFilter", k_SetUnhandledExceptionFilter},
    {"kernel32.dll", "SetUnhandledExceptionFilter", k_SetUnhandledExceptionFilter},
    {"kernel32.dll", "IsDebuggerPresent", k_IsDebuggerPresent},
    {"kernel32.dll", "EnterCriticalSection", k_EnterCriticalSection},
    {"kernel32.dll", "LeaveCriticalSection", k_LeaveCriticalSection},
    {"kernel32.dll", "DeleteCriticalSection", k_DeleteCriticalSection},
    {"kernel32.dll", "InitializeCriticalSectionAndSpinCount", k_InitializeCriticalSectionAndSpinCount},
    {"kernel32.dll", "WideCharToMultiByte", k_WideCharToMultiByte},
    {"kernel32.dll", "MultiByteToWideChar", k_MultiByteToWideChar},
    {"kernel32.dll", "GetConsoleCP", k_GetConsoleCP},
    {"kernel32.dll", "GetConsoleMode", k_GetConsoleMode},
    {"kernel32.dll", "GetConsoleOutputCP", k_GetConsoleOutputCP},
    {"kernel32.dll", "WriteConsoleA", k_WriteConsoleA},
    {"kernel32.dll", "WriteConsoleW", k_WriteConsoleW},
    {"kernel32.dll", "RaiseException", k_RaiseException},
    {"kernel32.dll", "RtlPcToFileHeader", k_RtlPcToFileHeader},
    {"kernel32.dll", "GetModuleHandleW", k_GetModuleHandleW},
    {"kernel32.dll", "GetProcAddress", k_GetProcAddress},
    {"kernel32.dll", "SetHandleCount", k_SetHandleCount},
    {"kernel32.dll", "GetStdHandle", k_GetStdHandle},
    {"kernel32.dll", "SetStdHandle", k_SetStdHandle},
    {"kernel32.dll", "GetFileType", k_GetFileType},
    {"kernel32.dll", "GetStartupInfoA", k_GetStartupInfoA},
    {"kernel32.dll", "GetStartupInfoW", k_GetStartupInfoW},
    {"kernel32.dll", "GetEnvironmentStrings", k_GetEnvironmentStrings},
    {"kernel32.dll", "GetEnvironmentStringsW", k_GetEnvironmentStringsW},
    {"kernel32.dll", "FreeEnvironmentStringsA", k_FreeEnvironmentStrings},
    {"kernel32.dll", "FreeEnvironmentStringsW", k_FreeEnvironmentStrings},
    {"kernel32.dll", "QueryPerformanceCounter", k_QueryPerformanceCounter},
    {"kernel32.dll", "GetSystemTimeAsFileTime", k_GetSystemTimeAsFileTime},
    {"kernel32.dll", "LCMapStringA", k_LCMapStringA},
    {"kernel32.dll", "LCMapStringW", k_LCMapStringW},
    {"kernel32.dll", "GetStringTypeA", k_GetStringTypeA},
    {"kernel32.dll", "GetStringTypeW", k_GetStringTypeW},
    {"kernel32.dll", "GetLocaleInfoA", k_GetLocaleInfoA},
    {"user32.dll", "wsprintfA", u_wsprintfA},
    {"advapi32.dll", "SetSecurityDescriptorSacl", a_true4},
    {"advapi32.dll", "InitializeSecurityDescriptor", a_true4},
    {"advapi32.dll", "SetSecurityDescriptorDacl", a_true4},
    {"advapi32.dll", "SetSecurityDescriptorGroup", a_true4},
    {"shell32.dll", "SHGetSpecialFolderPathA", s_SHGetSpecialFolderPathA},
    {"shlwapi.dll", "PathFileExistsA", s_PathFileExistsA},
    {NULL, NULL, NULL},
};

static void *lookup_stub(const char *dll, const char *name)
{
    for (const struct stub *s = stubs; s->name; s++)
        if (!strcasecmp(s->dll, dll) && !strcmp(s->name, name))
            return s->fn;
    return NULL;
}

/* Anything else traps with its name. Each gets a tiny thunk:
 *   movabs rdi, name ; movabs rax, missing_import ; call rax */
static void missing_import(const char *name)
{
    fprintf(stderr, "harness: unimplemented import %s called\n", name);
    abort();
}

static void *make_trap(const char *name)
{
    static uint8_t *pool;
    static size_t used;
    if (!pool || used + 32 > 65536) {
        pool = mmap(NULL, 65536, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        used = 0;
    }
    uint8_t *p = pool + used;
    char *copy = strdup(name);
    p[0] = 0x48, p[1] = 0xbf;
    memcpy(p + 2, &copy, 8);
    p[10] = 0x48, p[11] = 0xb8;
    void *fn = (void *)missing_import;
    memcpy(p + 12, &fn, 8);
    p[20] = 0xff, p[21] = 0xd0;
    used += 32;
    return p;
}

/* ------------------------------------------------------------------------ */
/* PE64 loader                                                               */

static uint8_t *img;

uint8_t *image_base(void) { return img; }

#define RD16(p) (*(const uint16_t *)(p))
#define RD32(p) (*(const uint32_t *)(p))
#define RD64(p) (*(const uint64_t *)(p))

void *pe_load(const char *path)
{
    FILE *f = fopen(path, "rb");
    if (!f) {
        perror(path);
        return NULL;
    }
    fseek(f, 0, SEEK_END);
    long fsz = ftell(f);
    fseek(f, 0, SEEK_SET);
    uint8_t *file = malloc(fsz);
    if (fread(file, 1, fsz, f) != (size_t)fsz) {
        fclose(f);
        return NULL;
    }
    fclose(f);

    uint8_t *nt = file + RD32(file + 0x3c);
    if (RD32(nt) != 0x4550) {
        fprintf(stderr, "not a PE file\n");
        return NULL;
    }
    uint8_t *fh = nt + 4;
    uint16_t nsect = RD16(fh + 2);
    uint16_t optsz = RD16(fh + 16);
    uint8_t *opt = fh + 20;
    if (RD16(opt) != 0x20b) {
        fprintf(stderr, "not PE32+\n");
        return NULL;
    }
    uint64_t pref_base = RD64(opt + 24);
    uint32_t size_image = RD32(opt + 56);
    uint32_t size_headers = RD32(opt + 60);
    uint32_t entry = RD32(opt + 16);
    uint8_t *dirs = opt + 112;
    uint8_t *sect = opt + optsz;

    img = mmap((void *)pref_base, size_image, PROT_READ | PROT_WRITE | PROT_EXEC,
               MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
    if (img == MAP_FAILED)
        img = mmap(NULL, size_image, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (img == MAP_FAILED) {
        perror("mmap");
        return NULL;
    }
    memcpy(img, file, size_headers);
    for (int i = 0; i < nsect; i++) {
        uint8_t *s = sect + i * 40;
        uint32_t va = RD32(s + 12), rawsz = RD32(s + 16), rawptr = RD32(s + 20);
        if (rawsz)
            memcpy(img + va, file + rawptr, rawsz);
    }

    /* relocations */
    int64_t delta = (int64_t)((uint64_t)img - pref_base);
    uint32_t rel_rva = RD32(dirs + 5 * 8), rel_sz = RD32(dirs + 5 * 8 + 4);
    if (delta && rel_rva) {
        uint8_t *r = img + rel_rva, *end = r + rel_sz;
        while (r < end) {
            uint32_t page = RD32(r), bsz = RD32(r + 4);
            if (!bsz)
                break;
            for (uint32_t k = 8; k < bsz; k += 2) {
                uint16_t e = RD16(r + k);
                if ((e >> 12) == 10)
                    *(uint64_t *)(img + page + (e & 0xfff)) += delta;
                else if ((e >> 12) == 3)
                    *(uint32_t *)(img + page + (e & 0xfff)) += (uint32_t)delta;
            }
            r += bsz;
        }
    }

    /* imports */
    uint32_t imp_rva = RD32(dirs + 1 * 8);
    for (uint8_t *d = img + imp_rva; imp_rva && RD32(d + 12); d += 20) {
        const char *dll = (const char *)img + RD32(d + 12);
        uint32_t oft = RD32(d) ? RD32(d) : RD32(d + 16);
        uint64_t *thunk = (uint64_t *)(img + oft);
        uint64_t *iat = (uint64_t *)(img + RD32(d + 16));
        for (; *thunk; thunk++, iat++) {
            char nbuf[128];
            const char *name;
            if (*thunk >> 63) {
                snprintf(nbuf, sizeof(nbuf), "%s#%u", dll, (unsigned)(*thunk & 0xffff));
                name = nbuf;
            } else {
                name = (const char *)img + (uint32_t)*thunk + 2;
            }
            void *fn = lookup_stub(dll, name);
            if (!fn) {
                char full[160];
                snprintf(full, sizeof(full), "%s!%s", dll, name);
                fn = make_trap(full);
            }
            *iat = (uint64_t)fn;
        }
    }
    free(file);

    /* Fake TEB at gs: MSVC's __chkstk reads gs:[0x10] (StackLimit). */
    uint8_t *teb = calloc(1, 0x2000);
    *(uint64_t *)(teb + 0x08) = ~0ull;  /* StackBase */
    *(uint64_t *)(teb + 0x10) = 0;      /* StackLimit */
    *(uint64_t *)(teb + 0x30) = (uint64_t)teb;
    syscall(SYS_arch_prctl, ARCH_SET_GS, teb);

    /* DllMain(hinst, DLL_PROCESS_ATTACH, NULL) */
    typedef BOOL (*WINAPI dllmain_t)(void *, DWORD, void *);
    dllmain_t dm = (dllmain_t)(img + entry);
    if (!dm(img, 1, NULL)) {
        fprintf(stderr, "DllMain failed\n");
        return NULL;
    }
    return img;
}

void *pe_export(const char *name)
{
    uint8_t *nt = img + RD32(img + 0x3c);
    uint8_t *dirs = nt + 4 + 20 + 112;
    uint32_t exp_rva = RD32(dirs);
    if (!exp_rva)
        return NULL;
    uint8_t *e = img + exp_rva;
    uint32_t n = RD32(e + 24);
    uint32_t *funcs = (uint32_t *)(img + RD32(e + 28));
    uint32_t *names = (uint32_t *)(img + RD32(e + 32));
    uint16_t *ords = (uint16_t *)(img + RD32(e + 36));
    for (uint32_t i = 0; i < n; i++)
        if (!strcmp((const char *)img + names[i], name))
            return img + funcs[ords[i]];
    return NULL;
}
