# SPDX-License-Identifier: GPL-2.0-or-later
"""Compile fprintd's Touch ID account binding against a fake passwd table.

Usage: test_account_binding.py path/to/fprintd/src/account_binding.c
"""

import os
import subprocess
import sys
import tempfile
from pathlib import Path

HARNESS = r'''
#include <assert.h>
#include <errno.h>
#include <pwd.h>
#include <stdio.h>
#include <string.h>
#include <glib.h>
#include <glib/gstdio.h>

/* The passwd table: one account, named `account_name` with `account_uid`,
 * or none when account_name is NULL. */
static const char *account_name;
static uid_t account_uid;

static int
fake_getpwnam_r (const char *name, struct passwd *entry, char *buffer,
                 size_t length, struct passwd **found)
{
  (void) buffer; (void) length;
  *found = NULL;
  if (account_name == NULL || strcmp (name, account_name) != 0)
    return 0;
  memset (entry, 0, sizeof (*entry));
  entry->pw_name = (char *) account_name;
  entry->pw_uid = account_uid;
  *found = entry;
  return 0;
}

#define getpwnam_r fake_getpwnam_r
#include "account_binding.c"
#undef getpwnam_r

#define DRIVER "apple-sep"
#define KEY7 "apple-sep/serial/7"
#define KEY8 "apple-sep/serial/8"

static char *base;

static void
store_print (const char *key)
{
  g_autofree char *path = g_build_filename (base, key, NULL);
  g_autofree char *dir = g_path_get_dirname (path);

  assert (g_mkdir_with_parents (dir, 0700) == 0);
  assert (g_file_set_contents (path, "print", -1, NULL));
}

static void
account (const char *name, uid_t uid)
{
  account_name = name;
  account_uid = uid;
}

static gboolean
bound (const char *key)
{
  return account_binding_is_bound (base, "alice", DRIVER, key);
}

static gboolean
bind (const char *key)
{
  g_autoptr(GError) error = NULL;

  store_print (key);
  return account_binding_bind (base, "alice", DRIVER, key, &error);
}

static char *
record_contents (void)
{
  g_autofree char *path = g_build_filename (base, ACCOUNT_BINDING_RECORD, NULL);
  char *contents = NULL;

  if (!g_file_get_contents (path, &contents, NULL, NULL))
    return NULL;
  return contents;
}

static void
rewrite_record (const char *from, const char *to)
{
  g_autofree char *path = g_build_filename (base, ACCOUNT_BINDING_RECORD, NULL);
  g_autofree char *contents = record_contents ();
  g_autoptr(GString) edited = g_string_new (contents);

  assert (contents != NULL);
  assert (g_string_replace (edited, from, to, 1) == 1);
  assert (g_file_set_contents (path, edited->str, -1, NULL));
}

static void
reset (void)
{
  g_autofree char *command = g_strdup_printf ("rm -rf '%s'", base);

  assert (system (command) == 0);
  assert (g_mkdir_with_parents (base, 0700) == 0);
}

int
main (int argc, char **argv)
{
  base = g_build_filename (argv[1], "alice", NULL);

  /* An enrolled print belongs to the account it was enrolled for. */
  reset ();
  account ("alice", 1001);
  assert (bind (KEY7));
  assert (bound (KEY7));

  /* Another account named alice, with another uid, does not get it, and its
   * own enrolment starts a new instance that the old print is not part of. */
  account ("alice", 1002);
  assert (!bound (KEY7));
  assert (bind (KEY8));
  assert (bound (KEY8));
  assert (!bound (KEY7));
  account ("alice", 1001);
  assert (!bound (KEY8));

  /* No account of that name: nothing is bound, and nothing can be bound. */
  account (NULL, 0);
  assert (!bound (KEY8));
  assert (!bind (KEY8));

  /* An invalidated record (account removal that could not delete the prints)
   * binds nothing, even for an account that has the old uid again. */
  reset ();
  account ("alice", 1001);
  assert (bind (KEY7));
  {
    g_autofree char *contents = record_contents ();
    g_autofree char *instance = NULL;
    char *at = strstr (contents, "Instance=");

    assert (at != NULL);
    instance = g_strndup (at, strcspn (at, "\n"));
    rewrite_record ("UID=1001", "UID=");
    rewrite_record (instance, "Instance=00000000-0000-4000-8000-000000000000");
  }
  assert (!bound (KEY7));
  /* Its next enrolment starts over; the old print stays unbound. */
  assert (bind (KEY8));
  assert (bound (KEY8));
  assert (!bound (KEY7));

  /* Prints stored before records existed are adopted together, once. */
  reset ();
  account ("alice", 1001);
  store_print (KEY7);
  store_print (KEY8);
  store_print ("apple-sep/serial/notes");
  assert (bound (KEY7));
  assert (bound (KEY8));
  assert (!bound ("apple-sep/serial/notes"));
  account ("alice", 1002);
  assert (!bound (KEY7));

  /* A record that exists but cannot be read adopts nothing. */
  reset ();
  account ("alice", 1001);
  store_print (KEY7);
  {
    g_autofree char *path = g_build_filename (base, ACCOUNT_BINDING_RECORD, NULL);

    assert (g_file_set_contents (path, "[Account\nnot a key file", -1, NULL));
  }
  assert (!bound (KEY7));

  /* A deleted print is forgotten; key file syntax in a key is escaped. */
  reset ();
  account ("alice", 1001);
  assert (bind (KEY7));
  account_binding_forget (base, KEY7);
  assert (!bound (KEY7));
  assert (bind ("apple-sep/odd [id]=x y/7"));
  assert (bound ("apple-sep/odd [id]=x y/7"));
  assert (!bound ("apple-sep/odd [id]=x y/8"));

  puts ("account binding: all checks passed");
  return 0;
}
'''


def main():
    source = Path(sys.argv[1]).resolve()
    flags = subprocess.run(["pkg-config", "--cflags", "--libs", "glib-2.0"],
                           check=True, capture_output=True, text=True).stdout.split()
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory)
        (path / "test.c").write_text(HARNESS)
        subprocess.run(["cc", "-std=gnu11", "-Wall", "-Werror", "-I", str(source.parent),
                        "test.c", "-o", "test", *flags], cwd=path, check=True)
        storage = path / "storage"
        storage.mkdir()
        subprocess.run([str(path / "test"), str(storage)], check=True)


if __name__ == "__main__":
    main()
