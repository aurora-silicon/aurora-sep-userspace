#!/usr/bin/python3
# SPDX-License-Identifier: MIT
"""pam_authenticate(SERVICE, USER) through libpam, for systems without pamtester.

Prompts are answered with empty strings; info and error messages are printed.
Exit 0 when PAM says PAM_SUCCESS.
"""

import ctypes
import ctypes.util
import sys

PAM_PROMPT_ECHO_OFF, PAM_PROMPT_ECHO_ON, PAM_ERROR_MSG, PAM_TEXT_INFO = 1, 2, 3, 4


class PamMessage(ctypes.Structure):
    _fields_ = [("msg_style", ctypes.c_int), ("msg", ctypes.c_char_p)]


class PamResponse(ctypes.Structure):
    _fields_ = [("resp", ctypes.c_void_p), ("resp_retcode", ctypes.c_int)]


CONV_FUNC = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_int,
                             ctypes.POINTER(ctypes.POINTER(PamMessage)),
                             ctypes.POINTER(ctypes.POINTER(PamResponse)), ctypes.c_void_p)


class PamConv(ctypes.Structure):
    _fields_ = [("conv", CONV_FUNC), ("appdata_ptr", ctypes.c_void_p)]


def main():
    service, user = sys.argv[1], sys.argv[2]
    pam = ctypes.CDLL(ctypes.util.find_library("pam") or "libpam.so.0")
    libc = ctypes.CDLL(None)
    libc.calloc.restype = ctypes.c_void_p
    libc.strdup.restype = ctypes.c_void_p
    libc.strdup.argtypes = [ctypes.c_char_p]

    def conv(n, msgs, resp, _data):
        arr = libc.calloc(n, ctypes.sizeof(PamResponse))
        resp[0] = ctypes.cast(arr, ctypes.POINTER(PamResponse))
        for i in range(n):
            m = msgs[i].contents
            text = (m.msg or b"").decode(errors="replace")
            if m.msg_style in (PAM_PROMPT_ECHO_OFF, PAM_PROMPT_ECHO_ON):
                print(f"prompt: {text}")
                resp[0][i].resp = libc.strdup(b"")
            else:
                print(f"{'error' if m.msg_style == PAM_ERROR_MSG else 'info'}: {text}")
        return 0

    cb = CONV_FUNC(conv)
    c = PamConv(cb, None)
    handle = ctypes.c_void_p()
    pam.pam_start.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.POINTER(PamConv),
                              ctypes.POINTER(ctypes.c_void_p)]
    pam.pam_strerror.restype = ctypes.c_char_p
    r = pam.pam_start(service.encode(), user.encode(), ctypes.byref(c), ctypes.byref(handle))
    if r != 0:
        print(f"pam_start: {r}")
        return 1
    r = pam.pam_authenticate(handle, 0)
    print(f"pam_authenticate: {pam.pam_strerror(handle, r).decode()}")
    pam.pam_end(handle, r)
    return 0 if r == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
