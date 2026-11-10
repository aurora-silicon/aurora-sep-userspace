# SPDX-License-Identifier: MIT
"""Installed paths. The aurora-fidod and aurora-fido wrappers set SEAL_HELPER
(and DOC) from the build's LIBEXECDIR and DOCDIR. No third-party imports, so
`aurora-fido status` works even when a dependency is missing."""

STATE_DIR = "/var/lib/aurora-fido"
RUN_DIR = "/run/aurora-fido"
CONFIG = "/etc/aurora-fido/aurora-fido.conf"
SEAL_HELPER = "/usr/libexec/aurora-fido/aurora-fido-seal"
DOC = "/usr/share/doc/aurora-fido/fido.md"
