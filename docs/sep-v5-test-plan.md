# SEP v4/v5 userspace qualification

Run the matrix below on the Neo before removing the kernel's v4 hold.
This is a test plan, not a record of hardware success. Package CI cannot prove
SEP persistence. Fedora, Arch Linux ARM and NixOS must ship the same libfprint
patch series and patched fprintd before a v5 fleet kernel is promoted.

| Kernel | Userspace | Required result |
| --- | --- | --- |
| fleet11b with the v4 hold | new packages | sensor gate and readiness pass; existing enrolments list and verify; a new enrolment works with the v4 ioctl |
| fleet kernel with enrol guards and without `7a4a84f9` | new packages | GET_INFO reports v5; sensor gate and readiness pass; existing enrolments list and verify; new enrolment survives reboot and verifies |
| same v5 kernel after another reboot | same packages | sensor and saved enrolments return without re-enrolment; verify succeeds |

## Prerequisites and evidence

An operator must approve hardware requests through the controller with explicit
`--device neo`, the qualification task and run IDs. Use the controller's source,
resource, session and ownership gates for **every** request, including install,
boot and rollback; never reach the target or its transports directly. An
interactive enrol/verify also needs the account owner's participation and an
approved interactive controller execution. Submit one bounded request at a time.
Do not reload `apple_sep` or restart its loader to switch kernels or packages.

Record the full kernel commit/release, package versions and hashes (all three
packages), boot ID, full dmesg and kernel journal per boot, readiness status,
fprintd journal, exit codes and controller request IDs. Save output in the
controller's private evidence directory. Account names, enrolment UUIDs, SEP
identity, calibration and state files must stay private; publish only aggregate
pass/fail results. Keep existing SEP identity, xART policy and persistent state
unchanged. Do not dump or restore old SEP/xART state as a rollback method.

For read-only captures, the operator can submit commands individually:

```sh
aurora-ctl hw request execute --device neo --task "$TASK" --run "$RUN" --mode shared --wait -- uname -r
aurora-ctl hw request execute --device neo --task "$TASK" --run "$RUN" --mode shared --wait -- cat /proc/sys/kernel/random/boot_id
aurora-ctl hw request execute --device neo --task "$TASK" --run "$RUN" --mode shared --wait -- dmesg
aurora-ctl hw request execute --device neo --task "$TASK" --run "$RUN" --mode shared --wait -- journalctl -b -k --no-pager
aurora-ctl hw request execute --device neo --task "$TASK" --run "$RUN" --mode shared --wait -- systemctl status aurora-sep-ready.service fprintd.service --no-pager
aurora-ctl hw request execute --device neo --task "$TASK" --run "$RUN" --mode shared --wait -- journalctl -b -u aurora-sep-ready -u fprintd --no-pager
```

The policy engine may classify a device-open/readiness or fprintd operation as
state-changing. Request exclusive mode and wait for approval where required.
Use `/usr/libexec/aurora-sep-sensor-present` on Fedora/Arch; on NixOS resolve
`pkgs.aurora-sep`'s `libexec/aurora/sensor-present` from the system closure.
The sensor gate must return zero on both ABIs. Readiness must reach its normal
restored/usable result, without a skipped ExecCondition or a new guard refusal.
Check GET_INFO's first two u32 fields using the installed sensor helper's
32-byte GET_INFO request; require `(4, 1)` or `(5, 1)` as appropriate.

## Procedure

1. On v4, capture the baseline and `fprintd-list "$TEST_USER"` privately.
   Verify an existing finger with `fprintd-verify -f "$EXISTING_FINGER" "$TEST_USER"`.
   Install the new libfprint, patched fprintd and aurora-sep together using the
   distro package manager/rebuild, through a separately approved controller
   request. Reboot through the approved controller boot route, preserving the
   known-good kernel entry and matching modules. Repeat list, readiness and
   verify. Require the same enrolments; never delete/re-enrol to make this pass.
2. If the owner authorizes a spare finger and a free slot, enrol it on v4 with
   `fprintd-enroll -f "$SPARE_FINGER" "$TEST_USER"`. Verify it. This tests the
   legacy 136-byte request rather than merely testing device discovery.
3. Build the fleet candidate from public source with the enrol-guard series
   present and `7a4a84f9` absent (preserve any unrelated fleet holds). Record
   the source/UAPI and the candidate's Image/module hashes. Use a controller-
   approved one-shot with the existing v4 kernel as fallback. Recheck actual
   boot identity and GET_INFO version 5 before claiming a v5 pass.
4. Repeat readiness, list and verify of the **existing** enrolments. With owner
   approval and another free slot, enrol a spare finger on v5, then verify it.
   Require a successful completed enrolment with no admission/persistence error.
   If no slot is free, stop that subtest and arrange an explicitly approved
   disposable enrolment; never delete another enrolment to make space.
5. Reboot the same v5 candidate via the controller. Require the new boot ID,
   readiness, the same saved finger list and successful verification of both
   the original and v5-enrolled fingers. Capture full logs again.
6. Boot the known-good v4 fallback with the new packages. Repeat discovery,
   readiness, list and verify, and capture any cross-version persistence
   failure. This proves rollback compatibility, not just initial v4 discovery.
7. Run the package/install matrix for all three distros on approved test
   installations while preserving each installation's identity and state.
   Do not assume a Fedora pass proves the Arch or NixOS unit/package paths.

Require errors for unresolved enrolment accounts and an already-enrolled finger
before starting a new enrolment. Use CI's simulated failed-device-delete tests
for deletion failures; never corrupt real persistence files to induce one.
Keep all failed attempts and their logs alongside successful runs.

## Rollback and hold removal

On failure, keep the hold and boot the known-good v4 entry through the controller.
The new userspace supports that kernel. Downgrade userspace only after the
running kernel is confirmed v4; restore package versions/units with the distro
package manager, and reboot through the controller. On NixOS use the previous
system generation together with its v4 kernel. Do not change identity, reset
Touch ID, restore stale state blobs or delete host records as a workaround.

Only propose removing the hold once the exact package builds pass CI, all three
distro PRs are ready, and the owner-assisted Neo persistence/verify matrix
passes. Removing the hold and fleet promotion are separate reviewed changes.
