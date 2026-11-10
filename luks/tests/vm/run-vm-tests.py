#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Boot the LUKS2-root VM through each initramfs and check how it unlocks.

Scenarios, for each initramfs builder (dracut, mkinitcpio):
  token     test plugin, valid token, headless: root opens with no prompt
  tampered  test plugin, token ciphertext flipped: passphrase prompt, then root
  no-sep    production plugin on a machine without a SEP: prompt comes quickly
            (no stall in the keyring), then root

Usage: run-vm-tests.py <dir with vmlinuz-*, initrd-*, root.img, root.uuid,
       root-tampered.img, pass> [builder ...]
"""
import os
import select
import subprocess
import sys
import time

D = sys.argv[1]
BUILDERS = sys.argv[2:] or ["dracut", "mkinitcpio"]
PASS = open(os.path.join(D, "pass")).read()
UUID = open(os.path.join(D, "root.uuid")).read().strip()
results = []


def boot(builder, kind, image, headless, answer, timeout=240):
    log_path = os.path.join(D, f"serial-{builder}-{kind}-{os.path.basename(image)}.log")
    opts = f"rd.luks.options={UUID}=headless=true" if headless else ""
    cmdline = (f"console=ttyS0 rd.luks.name={UUID}=root root=/dev/mapper/root rw "
               f"init=/sbin/vm-init {opts} systemd.show_status=1 loglevel=4 panic=-1")
    qemu = ["qemu-system-x86_64", "-enable-kvm", "-cpu", "host", "-m", "1024", "-smp", "2",
            "-display", "none", "-monitor", "none", "-serial", "stdio", "-no-reboot",
            "-kernel", os.path.join(D, f"vmlinuz-{builder}"),
            "-initrd", os.path.join(D, f"initrd-{builder}-{kind}.img"),
            "-drive", f"file={image},format=raw,if=virtio,snapshot=on",
            "-append", cmdline]
    p = subprocess.Popen(qemu, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                         stderr=subprocess.STDOUT)
    start = time.monotonic()
    buf = b""
    seen = {}
    answered = False
    with open(log_path, "wb") as log:
        while time.monotonic() - start < timeout:
            r, _, _ = select.select([p.stdout], [], [], 1.0)
            if r:
                chunk = os.read(p.stdout.fileno(), 65536)
                if not chunk:
                    break
                log.write(chunk)
                buf += chunk
                now = time.monotonic() - start
                for key, needle in (("crypt", b"Cryptography Setup for root"),
                                    ("prompt", b"assphrase for"),
                                    ("root", b"AURORA-SEP-VM-ROOT"),
                                    ("emergency", b"emergency mode"),
                                    ("sepload", b"aurora-sep-initrd")):
                    if key not in seen and needle in buf:
                        seen[key] = now
                if "prompt" in seen and answer and not answered:
                    time.sleep(0.5)
                    p.stdin.write(PASS.encode() + b"\r")
                    p.stdin.flush()
                    answered = True
                if "root" in seen and b"AURORA-SEP-VM-RUN" in buf:
                    break
                if "emergency" in seen:
                    break
            if p.poll() is not None:
                break
    if p.poll() is None:
        p.kill()
    p.wait()
    root_line = ""
    for line in buf.decode(errors="replace").splitlines():
        if line.startswith("AURORA-SEP-VM-ROOT"):
            root_line = line
    return seen, root_line, log_path


def record(name, ok, detail):
    results.append((name, ok))
    print(f"{'PASS' if ok else 'FAIL'} {name}: {detail}", flush=True)


for b in BUILDERS:
    seen, root, log = boot(b, "test", os.path.join(D, "root.img"), True, False)
    record(f"{b} token", "root" in seen and "prompt" not in seen and "/dev/mapper/root" in root,
           f"{root or 'no root'}; events {seen}; {log}")

    seen, root, log = boot(b, "test", os.path.join(D, "root-tampered.img"), False, True)
    record(f"{b} tampered token falls back to the passphrase",
           "prompt" in seen and "/dev/mapper/root" in root,
           f"{root or 'no root'}; events {seen}; {log}")

    seen, root, log = boot(b, "prod", os.path.join(D, "root.img"), False, True)
    wait = seen.get("prompt", 999) - seen.get("crypt", 0)
    record(f"{b} no SEP: prompt without a stall",
           "prompt" in seen and "/dev/mapper/root" in root and wait < 20,
           f"prompt {wait:.1f} s after cryptsetup started; {root or 'no root'}; events {seen}; {log}")

fails = sum(1 for _, ok in results if not ok)
print(f"vm: {len(results) - fails} passed, {fails} failed")
sys.exit(1 if fails else 0)
