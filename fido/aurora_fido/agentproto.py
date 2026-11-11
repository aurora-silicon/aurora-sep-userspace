# SPDX-License-Identifier: MIT
"""The wire between aurora-fidod (system, owns the uhid device) and
aurora-passkeyd (one per user, owns that user's credentials).

One CTAP2 request is one connection on a SOCK_SEQPACKET Unix socket. Every
message is one packet that holds one CBOR map; key "t" names the message:

  fidod -> agent   {"t": "req", "d": <CTAPHID_CBOR payload>}
  fidod -> agent   {"t": "cancel"}        the browser cancelled (CTAPHID_CANCEL)
  agent -> fidod   {"t": "up"}            waiting for the user (keepalive UPNEEDED)
  agent -> fidod   {"t": "resp", "d": <status || CBOR>}

If fidod closes the connection, that counts as a cancel. The agent never
trusts the peer for anything but framing. Signing still needs the enclave's
own Touch ID or password check. Peers are checked with SO_PEERCRED on both
sides (peer_uid).
"""

import socket
import struct

from . import cbor

MAX_PACKET = 16384          # a CTAP2 message is at most 7609 bytes; room for framing


class ProtocolError(Exception):
    pass


def send(sock, msg):
    data = cbor.encode(msg)
    if len(data) > MAX_PACKET:
        raise ProtocolError("message too large")
    sock.send(data)


def recv(sock):
    """One message, or None when the peer closed the connection."""
    data = sock.recv(MAX_PACKET)
    if not data:
        return None
    try:
        msg = cbor.decode(data)
    except cbor.CBORError as e:
        raise ProtocolError("bad message: %s" % e) from None
    if not isinstance(msg, dict) or not isinstance(msg.get("t"), str):
        raise ProtocolError("bad message")
    if msg["t"] in ("req", "resp") and not isinstance(msg.get("d"), bytes):
        raise ProtocolError("message without data")
    return msg


def peer_uid(sock):
    """The uid of the process at the other end (SO_PEERCRED)."""
    creds = sock.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
    _pid, uid, _gid = struct.unpack("3i", creds)
    return uid
