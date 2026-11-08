# SPDX-License-Identifier: MIT
"""A FIDO HID device through /dev/uhid (Documentation/hid/uhid.rst)."""

import os
import select
import struct

UHID_DESTROY = 1
UHID_START = 2
UHID_STOP = 3
UHID_OPEN = 4
UHID_CLOSE = 5
UHID_OUTPUT = 6
UHID_GET_REPORT = 9
UHID_GET_REPORT_REPLY = 10
UHID_CREATE2 = 11
UHID_INPUT2 = 12
UHID_SET_REPORT = 13
UHID_SET_REPORT_REPLY = 14

BUS_USB = 0x03
EVENT_SIZE = 4 + 4372        # sizeof(struct uhid_event): type + largest union member
DATA_MAX = 4096
REPORT_SIZE = 64

# FIDO Alliance usage page 0xF1D0, CTAPHID usage 0x01, 64-byte input and output reports.
REPORT_DESCRIPTOR = bytes([
    0x06, 0xD0, 0xF1,        # Usage Page (FIDO Alliance)
    0x09, 0x01,              # Usage (CTAPHID)
    0xA1, 0x01,              # Collection (Application)
    0x09, 0x20,              #   Usage (Input Report Data)
    0x15, 0x00,              #   Logical Minimum (0)
    0x26, 0xFF, 0x00,        #   Logical Maximum (255)
    0x75, 0x08,              #   Report Size (8)
    0x95, 0x40,              #   Report Count (64)
    0x81, 0x02,              #   Input (Data, Var, Abs)
    0x09, 0x21,              #   Usage (Output Report Data)
    0x15, 0x00,              #   Logical Minimum (0)
    0x26, 0xFF, 0x00,        #   Logical Maximum (255)
    0x75, 0x08,              #   Report Size (8)
    0x95, 0x40,              #   Report Count (64)
    0x91, 0x02,              #   Output (Data, Var, Abs)
    0xC0,                    # End Collection
])

NAME = "Aurora Touch ID Security Key"
# pid.codes (0x1209) test PID: no registered product ID yet. Nothing matches
# on it; udev finds the device by its FIDO usage page.
VENDOR = 0x1209
PRODUCT = 0x0001


def _pad(b):
    return b + b"\0" * (EVENT_SIZE - len(b))


class UhidDevice:
    def __init__(self, path="/dev/uhid", name=NAME, phys="aurora-fido", uniq=""):
        self.fd = os.open(path, os.O_RDWR | os.O_CLOEXEC)
        create = struct.pack(
            "<I128s64s64sHHIIII4096s", UHID_CREATE2,
            name.encode()[:127], phys.encode()[:63], uniq.encode()[:63],
            len(REPORT_DESCRIPTOR), BUS_USB, VENDOR, PRODUCT, 0x0100, 0,
            REPORT_DESCRIPTOR)
        os.write(self.fd, _pad(create))
        self.opened = False

    def send(self, report):
        """Send one 64-byte input report to the host side (hidraw readers)."""
        if len(report) != REPORT_SIZE:
            raise ValueError("report must be 64 bytes")
        os.write(self.fd, _pad(struct.pack("<IH", UHID_INPUT2, REPORT_SIZE) + report))

    def poll(self, timeout):
        """Next output report (64 bytes), or None when the timeout passed or the event was not one."""
        r, _, _ = select.select([self.fd], [], [], timeout)
        if not r:
            return None
        ev = os.read(self.fd, EVENT_SIZE)
        if len(ev) < 4:
            return None
        (etype,) = struct.unpack_from("<I", ev)
        if etype == UHID_OUTPUT:
            data, size, _rtype = struct.unpack_from(f"<{DATA_MAX}sHB", ev, 4)
            data = data[:min(size, DATA_MAX)]
            # hidraw passes the report number first (0: no report IDs).
            if len(data) == REPORT_SIZE + 1 and data[0] == 0:
                data = data[1:]
            return data[:REPORT_SIZE].ljust(REPORT_SIZE, b"\0")
        if etype == UHID_OPEN:
            self.opened = True
        elif etype == UHID_CLOSE:
            self.opened = False
        elif etype in (UHID_GET_REPORT, UHID_SET_REPORT):
            (rid,) = struct.unpack_from("<I", ev, 4)
            reply = UHID_GET_REPORT_REPLY if etype == UHID_GET_REPORT else UHID_SET_REPORT_REPLY
            # struct uhid_{get,set}_report_reply_req: id, err (EIO), size
            os.write(self.fd, _pad(struct.pack("<IIHH", reply, rid, 5, 0)))
        return None

    def close(self):
        try:
            os.write(self.fd, _pad(struct.pack("<I", UHID_DESTROY)))
        finally:
            os.close(self.fd)
