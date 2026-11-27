#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Checks the truncated host-state store repair against synthetic stores.

A repairable prefix is zero-extended with its bytes kept, a refused or
over-long file is left in place unchanged until an administrator runs
--reset, and a whole store is never read past its size. Every refusal
reason of the driver's format is produced by a store that fails exactly
that check. The quarantine keeps the newest two copies. Run from the
Makefile's check."""
import os
import runpy
import struct
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
SCRIPT = HERE.parent / 'aurora-sep-host-state-repair'

BLOCK = 0x8000
BLOCKS = 72
STORE_SIZE = BLOCK * BLOCKS
SLOTS = BLOCKS - 1
MAGIC = b'AURORA-SEP-STOR\x01'
KIND = 0xF1
SLOT_TABLE = 64
ENTRY = 24
TABLE_END = SLOT_TABLE + SLOTS * ENTRY


def superblock(used=(), generation=7, intent_kind=0, intent_slot=0,
               intent_type=0, slot_count=SLOTS, block_size=BLOCK, version=1):
    """The writer's superblock: the fixed geometry, `used` slot entries as
    (index, kind, uuid, length) and the copy-on-write intent."""
    sb = bytearray(BLOCK)
    sb[0:16] = MAGIC
    struct.pack_into('<I', sb, 16, version)
    struct.pack_into('<I', sb, 20, slot_count)
    struct.pack_into('<I', sb, 24, block_size)
    struct.pack_into('<Q', sb, 28, generation)
    sb[36] = intent_kind
    struct.pack_into('<H', sb, 37, intent_slot)
    sb[39] = intent_type
    for index, kind, uuid, length in used:
        off = SLOT_TABLE + index * ENTRY
        sb[off] = 1
        sb[off + 1] = kind
        sb[off + 2:off + 18] = uuid
        struct.pack_into('<I', sb, off + 18, length)
    return bytes(sb)


def slot_entry(sb, index):
    off = SLOT_TABLE + index * ENTRY
    return off, sb[off:off + ENTRY]


def data(index, length):
    return bytes((index * 31 + i) & 0xFF for i in range(length))


def make_file(path, sb, slots=(), cut=None, extra=b''):
    """Writes the superblock, each (index, bytes) slot's data at its block,
    then cuts the file to `cut` and appends `extra` past a whole store."""
    end = max([(i + 1) * BLOCK + len(d) for i, d in slots] + [cut or 0, BLOCK])
    buf = bytearray(max(end, STORE_SIZE))
    buf[0:BLOCK] = sb
    for i, d in slots:
        start = (i + 1) * BLOCK
        buf[start:start + len(d)] = d
    if cut is not None:
        buf = buf[:cut]
    buf += extra
    Path(path).write_bytes(buf)
    return bytes(buf)


class Repair(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = Path(self.tmp.name) / 'aurora-sep-host-state.bin'
        self.quarantine = Path(self.tmp.name) / 'quarantine'

    def tearDown(self):
        self.tmp.cleanup()

    def repair(self, *args, **extra_env):
        env = dict(os.environ,
                   AURORA_SEP_HOST_STATE=str(self.store),
                   AURORA_SEP_QUARANTINE=str(self.quarantine))
        env.pop('JOURNAL_STREAM', None)
        env.update(extra_env)
        return subprocess.run([sys.executable, str(SCRIPT), *args], env=env,
                               capture_output=True, text=True, check=False)

    def backups(self):
        if not self.quarantine.exists():
            return []
        return sorted(self.quarantine.glob('host-state-managed-*.bin'))

    def refuse(self, reason):
        """The store stays in place, unchanged, with no copy made, and the
        log names the reason and the administrator's reset command."""
        result = self.repair()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(reason, result.stdout)
        self.assertIn(f'left {self.store} in place, unchanged', result.stdout)
        self.assertIn('Touch ID stays off', result.stdout)
        self.assertIn(f'{SCRIPT} --reset', result.stdout)
        self.assertEqual(self.store.read_bytes(), self.original)
        self.assertEqual(self.backups(), [])
        # Every boot finds it the same way, and nothing piles up.
        again = self.repair()
        self.assertEqual(again.returncode, 0, again.stderr)
        self.assertEqual(self.store.read_bytes(), self.original)
        self.assertEqual(self.backups(), [])
        return result

    def test_whole_store_is_untouched(self):
        original = make_file(self.store, superblock(used=[(0, KIND, b'0' * 16, 0x100)]),
                             slots=[(0, data(0, 0x100))])
        result = self.repair()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, '')
        self.assertEqual(self.store.read_bytes(), original)
        self.assertEqual(self.backups(), [])

    def test_whole_store_with_a_damaged_superblock_is_untouched(self):
        sb = bytearray(superblock(used=[(0, KIND, b'0' * 16, 0x100)]))
        sb[0:16] = b'not the magic   '
        original = make_file(self.store, bytes(sb), slots=[(0, data(0, 0x100))])
        result = self.repair()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, '')
        self.assertEqual(self.store.read_bytes(), original)
        self.assertEqual(self.backups(), [])

    def test_missing_store(self):
        result = self.repair()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('no host-state store yet', result.stdout)
        self.assertFalse(self.quarantine.exists())

    def test_empty_and_all_zero_files_are_left_to_the_driver(self):
        self.store.write_bytes(b'')
        result = self.repair()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('holds no state', result.stdout)
        self.assertEqual(self.store.read_bytes(), b'')
        self.assertEqual(self.backups(), [])

        self.store.write_bytes(b'\0' * (5 * BLOCK))
        result = self.repair()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('holds no state', result.stdout)
        self.assertEqual(self.store.read_bytes(), b'\0' * (5 * BLOCK))
        self.assertEqual(self.backups(), [])

    def test_repairable_prefix_is_zero_extended(self):
        sb = superblock(used=[(0, KIND, b'0' * 16, 0x1000),
                               (1, KIND, b'1' * 16, 0x2000)])
        cut = 3 * BLOCK - 0x1234
        self.original = make_file(self.store, sb,
                                  slots=[(0, data(0, 0x1000)), (1, data(1, 0x2000))],
                                  cut=cut)
        result = self.repair()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('zero-extended', result.stdout)
        self.assertEqual(self.store.stat().st_size, STORE_SIZE)
        repaired = self.store.read_bytes()
        self.assertEqual(repaired[:cut], self.original)
        self.assertEqual(repaired[cut:], b'\0' * (STORE_SIZE - cut))
        copies = self.backups()
        self.assertEqual(len(copies), 1)
        self.assertEqual(copies[0].stat().st_size, cut)
        self.assertEqual(copies[0].read_bytes(), self.original)

    def test_prefix_with_no_used_slots_is_extended(self):
        self.original = make_file(self.store, superblock(), cut=BLOCK + 5)
        result = self.repair()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('zero-extended', result.stdout)
        self.assertEqual(self.store.stat().st_size, STORE_SIZE)
        self.assertEqual(self.store.read_bytes()[:BLOCK + 5], self.original)
        self.assertEqual(self.store.read_bytes()[BLOCK + 5:], b'\0' * (STORE_SIZE - BLOCK - 5))
        self.assertEqual(len(self.backups()), 1)

    def test_intent_naming_a_free_slot_is_kept(self):
        sb = superblock(used=[(0, KIND, b'0' * 16, 0x100)],
                        intent_kind=1, intent_slot=5, intent_type=0xF2)
        cut = 2 * BLOCK
        self.original = make_file(self.store, sb, slots=[(0, data(0, 0x100))], cut=cut)
        result = self.repair()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('zero-extended', result.stdout)
        self.assertEqual(self.store.stat().st_size, STORE_SIZE)
        self.assertEqual(self.store.read_bytes()[:cut], self.original)

    def test_slot_cut_off_mid_value(self):
        sb = superblock(used=[(1, KIND, b'1' * 16, 0x2000)])
        self.original = make_file(self.store, sb, slots=[(1, data(1, 0x2000))],
                                  cut=2 * BLOCK + 0x1000)
        self.refuse('a used slot ends past the file')

    def test_superblock_shorter_than_the_slot_table(self):
        self.original = make_file(self.store, superblock(), cut=100)
        self.refuse('superblock too short')

    def test_bad_magic(self):
        sb = bytearray(superblock(used=[(0, KIND, b'0' * 16, 0x100)]))
        sb[3] ^= 0xFF
        self.original = make_file(self.store, bytes(sb), cut=3 * BLOCK)
        self.refuse('bad magic')

    def test_unsupported_version(self):
        self.original = make_file(self.store, superblock(version=2), cut=2 * BLOCK)
        self.refuse('unsupported version')

    def test_slot_count_mismatch(self):
        self.original = make_file(self.store, superblock(slot_count=SLOTS + 1),
                                  cut=2 * BLOCK)
        self.refuse('slot count mismatch')

    def test_block_size_mismatch(self):
        self.original = make_file(self.store, superblock(block_size=0x4000),
                                  cut=2 * BLOCK)
        self.refuse('block size mismatch')

    def test_reserved_header_bytes(self):
        sb = bytearray(superblock(used=[(0, KIND, b'0' * 16, 0x100)]))
        sb[45] = 1
        self.original = make_file(self.store, bytes(sb), cut=2 * BLOCK)
        self.refuse('reserved header bytes are set')

    def test_reserved_superblock_tail(self):
        sb = bytearray(superblock(used=[(0, KIND, b'0' * 16, 0x100)]))
        sb[TABLE_END] = 1
        self.original = make_file(self.store, bytes(sb), cut=2 * BLOCK)
        self.refuse('reserved superblock bytes are set')

    def test_slot_used_flag(self):
        sb = bytearray(superblock(used=[(0, KIND, b'0' * 16, 0x100)]))
        off, _ = slot_entry(sb, 0)
        sb[off] = 2
        self.original = make_file(self.store, bytes(sb), cut=2 * BLOCK)
        self.refuse('slot 0: bad used flag')

    def test_slot_unknown_kind(self):
        self.original = make_file(self.store, superblock(used=[(0, 0xF6, b'0' * 16, 0x100)]),
                                   cut=2 * BLOCK)
        self.refuse('slot 0: unknown kind')

    def test_slot_value_too_large(self):
        self.original = make_file(self.store, superblock(used=[(0, KIND, b'0' * 16, BLOCK + 1)]),
                                   cut=2 * BLOCK)
        self.refuse('slot 0: value too large')

    def test_slot_reserved_tail(self):
        sb = bytearray(superblock(used=[(0, KIND, b'0' * 16, 0x100)]))
        off, _ = slot_entry(sb, 0)
        sb[off + 23] = 1
        self.original = make_file(self.store, bytes(sb), cut=2 * BLOCK)
        self.refuse('slot 0: reserved bytes are set')

    def test_duplicate_slot_keys(self):
        self.original = make_file(
            self.store,
            superblock(used=[(0, KIND, b'same uuid here!', 0x100),
                             (1, KIND, b'same uuid here!', 0x100)]),
            cut=2 * BLOCK)
        self.refuse('slot 1: duplicate key')

    def test_intent_names_a_used_slot(self):
        self.original = make_file(
            self.store,
            superblock(used=[(0, KIND, b'0' * 16, 0x100)],
                       intent_kind=1, intent_slot=0, intent_type=KIND),
            cut=2 * BLOCK)
        self.refuse('intent names a used slot')

    def test_intent_out_of_range(self):
        self.original = make_file(self.store,
                                   superblock(intent_kind=1, intent_slot=SLOTS,
                                              intent_type=KIND),
                                   cut=2 * BLOCK)
        self.refuse('intent names an out-of-range slot')

    def test_intent_unknown_kind(self):
        self.original = make_file(self.store, superblock(intent_kind=1, intent_slot=5,
                                                         intent_type=0xF6),
                                   cut=2 * BLOCK)
        self.refuse('intent has an unknown kind')

    def test_unknown_intent(self):
        self.original = make_file(self.store, superblock(intent_kind=2, intent_slot=5,
                                                         intent_type=KIND),
                                   cut=2 * BLOCK)
        self.refuse('unknown intent')

    def test_bad_empty_intent(self):
        self.original = make_file(self.store, superblock(intent_slot=1), cut=2 * BLOCK)
        self.refuse('bad empty intent')

    def test_file_longer_than_a_store_is_left_in_place(self):
        self.original = make_file(self.store, superblock(), cut=None,
                                  extra=b'\x5A' * BLOCK)
        self.refuse('longer than a store')

    def test_all_zero_file_longer_than_a_store_is_left_in_place(self):
        self.original = make_file(self.store, b'\0' * BLOCK, cut=None,
                                  extra=b'\0' * (BLOCK + 1))
        self.refuse('bad magic')

    def test_store_cut_inside_the_slot_table_is_left_in_place(self):
        # Any cut before the end of the slot table, with any byte set.
        for cut in (1, 64, TABLE_END - 1):
            with self.subTest(cut=cut):
                self.original = make_file(self.store, superblock(), cut=cut)
                self.refuse('superblock too short')

    def test_refusal_is_a_journal_warning_under_systemd(self):
        self.original = make_file(self.store, superblock(), cut=100)
        result = self.repair(JOURNAL_STREAM='8:1234')
        lines = [l for l in result.stdout.splitlines() if 'in place' in l]
        self.assertEqual(len(lines), 1)
        self.assertTrue(lines[0].startswith('<4>aurora-sep-host-state-repair: '), lines[0])
        # By hand, the line carries no priority prefix.
        result = self.repair()
        self.assertTrue(all(l.startswith('aurora-sep-host-state-repair: ')
                            for l in result.stdout.splitlines()), result.stdout)

    def test_reset_moves_a_refused_store_aside(self):
        self.original = make_file(self.store, superblock(), cut=100)
        self.refuse('superblock too short')
        result = self.repair('--reset')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('creates a fresh store', result.stdout)
        self.assertFalse(self.store.exists())
        copies = self.backups()
        self.assertEqual(len(copies), 1)
        self.assertEqual(copies[0].read_bytes(), self.original)
        self.assertEqual(copies[0].stat().st_mode & 0o777, 0o600)

    def test_reset_preserves_store_and_older_copies_if_quarantine_sync_fails(self):
        original = b'refused store'
        self.store.write_bytes(original)
        self.quarantine.mkdir()
        older_copies = [
            self.quarantine / f'host-state-managed-202512{day}-000000-100.bin'
            for day in (10, 11)
        ]
        for path in older_copies:
            path.write_bytes(b'older copy')

        with patch.dict(os.environ, AURORA_SEP_HOST_STATE=str(self.store),
                        AURORA_SEP_QUARANTINE=str(self.quarantine)):
            reset = runpy.run_path(str(SCRIPT))['reset']
        with patch.dict(reset.__globals__, {
            'sync_directory': self.fail_directory_sync,
        }):
            self.assertEqual(reset(), 1)

        self.assertEqual(self.store.read_bytes(), original)
        for path in older_copies:
            self.assertEqual(path.read_bytes(), b'older copy')

    def fail_directory_sync(self, path):
        self.assertEqual(Path(path), self.quarantine)
        raise OSError('simulated directory sync failure')

    def test_reset_leaves_a_whole_store_alone(self):
        original = make_file(self.store, superblock())
        result = self.repair('--reset')
        self.assertEqual(result.returncode, 1)
        self.assertIn('full size', result.stdout)
        self.assertEqual(self.store.read_bytes(), original)
        self.assertEqual(self.backups(), [])

    def test_reset_without_a_store(self):
        result = self.repair('--reset')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('nothing to reset', result.stdout)
        self.assertFalse(self.quarantine.exists())

    def test_unknown_arguments_change_nothing(self):
        self.original = make_file(self.store, superblock(), cut=100)
        for args in (['--rest'], ['--reset', 'x'], ['-h']):
            with self.subTest(args=args):
                result = self.repair(*args)
                self.assertEqual(result.returncode, 2)
                self.assertIn('usage', result.stderr)
                self.assertEqual(self.store.read_bytes(), self.original)
                self.assertFalse(self.quarantine.exists())

    def repairable(self, tag):
        sb = superblock(used=[(0, KIND, b'0' * 16, 0x100)], generation=tag)
        return make_file(self.store, sb, slots=[(0, data(tag, 0x100))], cut=2 * BLOCK)

    def test_quarantine_permissions_and_unique_names(self):
        for tag in range(2):
            self.original = self.repairable(tag)
            result = self.repair()
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn('zero-extended', result.stdout)
            self.store.write_bytes(self.original)
        copies = self.backups()
        self.assertEqual(len(copies), 2)
        self.assertEqual(len({c.name for c in copies}), 2)
        self.assertEqual(self.quarantine.stat().st_mode & 0o777, 0o700)
        for copy in copies:
            self.assertEqual(copy.stat().st_mode & 0o777, 0o600)

    def test_quarantine_keeps_the_newest_two_copies(self):
        self.quarantine.mkdir(mode=0o700)
        old = []
        for age, name in ((300, 'host-state-managed-20260101-000000-100.bin'),
                          (200, 'host-state-managed-20260102-000000-100.bin'),
                          (100, 'host-state-managed-20260103-000000-100.bin')):
            path = self.quarantine / name
            path.write_bytes(name.encode())
            stamp = time.time() - age
            os.utime(path, (stamp, stamp))
            old.append(path)
        legacy = [self.quarantine / f'host-state-202512{day}-000000-100.bin'
                  for day in (10, 11)]
        for path in legacy:
            path.write_bytes(path.name.encode())
        # Another file and a link that matches the managed pattern.
        other = self.quarantine / 'notes.txt'
        other.write_text('kept')
        outside = Path(self.tmp.name) / 'outside.bin'
        outside.write_text('kept')
        link = self.quarantine / 'host-state-managed-link.bin'
        link.symlink_to(outside)
        os.utime(link, (0, 0), follow_symlinks=False)

        self.original = self.repairable(7)
        result = self.repair()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('zero-extended', result.stdout)
        copies = sorted(p for p in self.quarantine.iterdir()
                        if p.is_file() and not p.is_symlink() and p.name.startswith('host-state-managed-'))
        new = [p for p in copies if p not in old]
        self.assertEqual(len(new), 1)
        self.assertEqual(new[0].read_bytes(), self.original)
        # The new copy and the newest older one; the two oldest are gone.
        self.assertEqual(sorted(copies), sorted(new + [old[2]]))
        self.assertFalse(old[0].exists())
        self.assertFalse(old[1].exists())
        for path in legacy:
            self.assertEqual(path.read_bytes(), path.name.encode())
        self.assertEqual(other.read_text(), 'kept')
        self.assertTrue(link.is_symlink())
        self.assertEqual(outside.read_text(), 'kept')


if __name__ == '__main__':
    unittest.main()
