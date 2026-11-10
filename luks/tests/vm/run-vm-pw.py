#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Boot the password-mode LUKS2 root (aurora-sep-fde, FileVault model) through
the initramfs, answering the prompts the way a user at the Plymouth screen
would, against the enclave double the image carries.

  right      the token PIN prompt takes the user's password: root opens
  wrong      a wrong password is refused, the prompt comes back, the right one opens
  recovery   the recovery key typed loosely (lower case, no dashes) at the same prompt
  nosep      no SEP on this Mac: the password cannot be checked, systemd falls
             back to the passphrase prompt and the recovery key opens its
             offline keyslot (never a brick)
  tampered   the enclave refuses the user token: passphrase prompt, recovery key

Usage: run-vm-pw.py <dir from run-all.sh> [builder ...]
"""
import os
import select
import subprocess
import sys
import time

D = sys.argv[1]
BUILDERS = sys.argv[2:] or ["dracut"]
PW = open(os.path.join(D, "pw")).read()
BAD = open(os.path.join(D, "pw-bad")).read()
RK = open(os.path.join(D, "rk")).read().strip()
UUID = open(os.path.join(D, "root.uuid")).read().strip()
PIN = b"token PIN"
PASS = b"assphrase for"
results = []


def boot(builder, kind, image, answers, timeout=240):
    """answers: list of (prompt needle, text); each is sent when that prompt
    appears for the n-th time overall."""
    log_path = os.path.join(D, f"serial-pw-{builder}-{kind}-{os.path.basename(image)}.log")
    cmdline = (f"console=ttyS0 rd.luks.name={UUID}=root root=/dev/mapper/root rw "
               f"init=/sbin/vm-init systemd.show_status=1 loglevel=4 panic=-1")
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
    prompts = []          # (needle, time) in order of appearance
    sent = 0
    counts = {PIN: 0, PASS: 0}
    with open(log_path, "wb") as log:
        while time.monotonic() - start < timeout:
            r, _, _ = select.select([p.stdout], [], [], 1.0)
            if r:
                chunk = os.read(p.stdout.fileno(), 65536)
                if not chunk:
                    break
                log.write(chunk)
                buf += chunk
                for needle in (PIN, PASS):
                    n = buf.count(needle)
                    while counts[needle] < n:
                        counts[needle] += 1
                        prompts.append((needle, time.monotonic() - start))
                while sent < len(answers) and sent < len(prompts):
                    want, text = answers[sent]
                    got = prompts[sent][0]
                    if got != want:
                        break
                    time.sleep(0.5)
                    p.stdin.write(text.encode() + b"\r")
                    p.stdin.flush()
                    sent += 1
                if b"AURORA-SEP-VM-RUN" in buf or b"emergency mode" in buf:
                    break
            if p.poll() is not None:
                break
    if p.poll() is None:
        p.kill()
    p.wait()
    root = ""
    for line in buf.decode(errors="replace").splitlines():
        if line.startswith("AURORA-SEP-VM-ROOT"):
            root = line
    order = [("PIN" if n == PIN else "PASS") for n, _ in prompts]
    return order, root, log_path


def record(name, ok, detail):
    results.append((name, ok))
    print(f"{'PASS' if ok else 'FAIL'} {name}: {detail}", flush=True)


loose = RK.lower().replace("-", "")
img = os.path.join(D, "root-pw.img")
bad_img = os.path.join(D, "root-pw-tampered.img")
for b in BUILDERS:
    order, root, log = boot(b, "pw", img, [(PIN, PW)])
    record(f"{b} password at the token prompt opens root",
           "/dev/mapper/root" in root and order[:1] == ["PIN"] and "PASS" not in order,
           f"prompts {order}; {root or 'no root'}; {log}")

    order, root, log = boot(b, "pw", img, [(PIN, BAD), (PIN, PW)])
    record(f"{b} wrong password refused, prompt again, right one opens",
           "/dev/mapper/root" in root and order[:2] == ["PIN", "PIN"] and "PASS" not in order,
           f"prompts {order}; {root or 'no root'}; {log}")

    order, root, log = boot(b, "pw", img, [(PIN, loose)])
    record(f"{b} recovery key at the token prompt opens root",
           "/dev/mapper/root" in root and "PASS" not in order,
           f"prompts {order}; {root or 'no root'}; {log}")

    order, root, log = boot(b, "pwnosep", img, [(PIN, PW), (PASS, RK)])
    record(f"{b} no SEP: passphrase prompt, recovery key opens the offline keyslot",
           "/dev/mapper/root" in root and order[:2] == ["PIN", "PASS"],
           f"prompts {order}; {root or 'no root'}; {log}")

    order, root, log = boot(b, "pw", bad_img, [(PIN, PW), (PASS, RK)])
    record(f"{b} enclave refuses the token: passphrase prompt, recovery key opens",
           "/dev/mapper/root" in root and order[:2] == ["PIN", "PASS"],
           f"prompts {order}; {root or 'no root'}; {log}")

fails = sum(1 for _, ok in results if not ok)
print(f"vm-pw: {len(results) - fails} passed, {fails} failed")
sys.exit(1 if fails else 0)
