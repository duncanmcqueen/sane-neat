// SPDX-License-Identifier: GPL-2.0-or-later WITH SANE-exception
/* ND-1000 discovery. Default invocation does not send any USB transfers. */
#include <libusb-1.0/libusb.h>
#include <stdio.h>
#include <string.h>

#define NEAT_VID 0x1f44
#define ND1000_PID 0x0050

int main(int argc, char **argv)
{
    libusb_context *ctx = NULL;
    libusb_device **devices = NULL;
    ssize_t count;
    int found = 0;
    int read_failed = 0;
    int query = argc == 2 && !strcmp(argv[1], "--read-register-41");

    if (argc > 2 || (argc == 2 && !query)) {
        fprintf(stderr, "usage: %s [--read-register-41]\n", argv[0]);
        return 2;
    }
    if (libusb_init(&ctx) != 0)
        return 1;
    count = libusb_get_device_list(ctx, &devices);
    if (count < 0) {
        fprintf(stderr, "USB enumeration failed: %s\n", libusb_error_name((int)count));
        libusb_exit(ctx);
        return 1;
    }
    for (ssize_t i = 0; i < count; i++) {
        struct libusb_device_descriptor desc;
        libusb_device_handle *handle = NULL;
        if (libusb_get_device_descriptor(devices[i], &desc) ||
            desc.idVendor != NEAT_VID || desc.idProduct != ND1000_PID)
            continue;
        found = 1;
        printf("ND-1000 candidate %04x:%04x bus %u address %u USB %x.%02x firmware %x.%02x\n",
               desc.idVendor, desc.idProduct, libusb_get_bus_number(devices[i]),
               libusb_get_device_address(devices[i]), desc.bcdUSB >> 8, desc.bcdUSB & 0xff,
               desc.bcdDevice >> 8, desc.bcdDevice & 0xff);
        if (!query)
            continue;
        int rc = libusb_open(devices[i], &handle);
        if (rc != 0) {
            fprintf(stderr, "Cannot open USB device: %s (check udev ACL)\n", libusb_error_name(rc));
            libusb_free_device_list(devices, 1);
            libusb_exit(ctx);
            return 1;
        }
        /* The NM-1000 uses a Genesys register read, returning a byte plus
         * 0x55 status. This is an explicitly requested read-only probe;
         * a matching response is a clue, not proof of shared hardware. */
        unsigned char response[2] = {0};
        rc = libusb_control_transfer(handle, 0xc0, 0x04, 0x008e, 0x4122,
                                     response, sizeof(response), 1000);
        if (rc == 2) {
            printf("register 0x41: %02x, status: %02x (%s)\n", response[0], response[1],
                   response[1] == 0x55 ? "NM-style response" : "different response");
            if (response[1] != 0x55)
                read_failed = 1;
        } else {
            printf("register read unsupported or failed: %s\n",
                   rc < 0 ? libusb_error_name(rc) : "short response");
            read_failed = 1;
        }
        libusb_close(handle);
    }
    libusb_free_device_list(devices, 1);
    libusb_exit(ctx);
    if (!found)
        fprintf(stderr, "No 1f44:0050 device found\n");
    return found && !read_failed ? 0 : 1;
}
