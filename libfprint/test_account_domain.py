# SPDX-License-Identifier: MIT
"""Compile the driver's account choice for a match with stand-in prints and a
stand-in passwd database, and check when a verify or an identify names the
Unix account (SEP_BIO_VERIFY_ACCOUNT):
  - only when the open device offered SEP_BIO_INFO_VERIFY_ACCOUNT, which the
    open reads from GET_INFO once; a match never asks again, so a query the
    kernel refuses between touches cannot move a retry to another domain;
  - with the uid of the print's account, resolved by its exact name;
  - for an identify, only when every print in the gallery is that account's;
  - never for a print without an account, or one whose name has no passwd
    entry, which keep the built-in Linux user as before.
Then check that the open records the flag and the match start passes the
choice in the verify request.
"""
import re
import subprocess
import sys
import tempfile
from pathlib import Path


def function(source, name):
    match = re.search(r'^' + name + r' \(', source, re.M)
    if match is None:
        raise AssertionError(f'missing {name}')
    opening = source.index('{', match.start())
    depth, end = 1, opening + 1
    while depth:
        depth += (source[end] == '{') - (source[end] == '}')
        end += 1
    return source[match.start():end]


HARNESS = r'''
#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <string.h>
#include <pwd.h>
#include "apple-sep.h"
typedef uint32_t guint32;
typedef uint64_t guint64;
typedef unsigned int guint;
typedef char gchar;
typedef int gboolean;
#define TRUE 1
#define FALSE 0
#define G_MAXUINT32 UINT32_MAX
typedef struct { int fd; gboolean verify_account; } FpiDeviceAurora;
typedef struct { const char *username; } FpPrint;
static int g_strcmp0 (const char *a, const char *b)
{
  if (a == NULL || b == NULL)
    return a == b ? 0 : (a == NULL ? -1 : 1);
  return strcmp (a, b);
}
static const gchar *fp_print_get_username (FpPrint *print) { return print->username; }

/* A match must not query the device: it decides from the open's flag. */
static int __attribute__ ((unused)) fake_ioctl (int fd, unsigned long req, void *arg)
{
  (void) fd; (void) req; (void) arg;
  assert (!"a match queried the device");
  return -1;
}
#define ioctl fake_ioctl

/* passwd: alice is 1000, and "Alice" is not alice. */
static int fake_getpwnam_r (const char *name, struct passwd *pw, char *buf,
                            size_t len, struct passwd **out)
{
  (void) buf; (void) len;
  *out = NULL;
  if (strcmp (name, "alice") == 0)
    {
      memset (pw, 0, sizeof (*pw));
      pw->pw_name = "alice";
      pw->pw_uid = 1000;
      *out = pw;
    }
  else if (strcmp (name, "Alice") == 0)
    {
      /* A case-insensitive passwd source answering for alice. */
      memset (pw, 0, sizeof (*pw));
      pw->pw_name = "alice";
      pw->pw_uid = 1000;
      *out = pw;
    }
  return 0;
}
#define getpwnam_r fake_getpwnam_r

static gboolean
@ACCOUNT@
int main (void)
{
  FpiDeviceAurora dev = { 42, FALSE };
  FpPrint alice = { "alice" }, bob = { "bob" }, none = { NULL }, empty = { "" };
  FpPrint upper = { "Alice" };
  FpPrint *one[] = { &alice }, *same[] = { &alice, &alice }, *mixed[] = { &alice, &bob };
  FpPrint *nobody[] = { &bob }, *unnamed[] = { &none }, *blank[] = { &empty };
  FpPrint *cased[] = { &upper }, *missing[] = { NULL };
  guint32 uid = 0;

  /* A device opened without the flag: never named, as before. */
  assert (!aurora_match_account (&dev, one, 1, &uid));
  dev.verify_account = TRUE;

  assert (aurora_match_account (&dev, one, 1, &uid) && uid == 1000);
  uid = 0;
  assert (aurora_match_account (&dev, same, 2, &uid) && uid == 1000);
  /* A gallery naming two accounts keeps the built-in user. */
  assert (!aurora_match_account (&dev, mixed, 2, &uid));
  /* No account, an empty name, no passwd entry, or a passwd entry for
   * another spelling: the built-in user. */
  assert (!aurora_match_account (&dev, unnamed, 1, &uid));
  assert (!aurora_match_account (&dev, blank, 1, &uid));
  assert (!aurora_match_account (&dev, nobody, 1, &uid));
  assert (!aurora_match_account (&dev, cased, 1, &uid));
  assert (!aurora_match_account (&dev, missing, 1, &uid));
  assert (!aurora_match_account (&dev, one, 0, &uid));
  return 0;
}
'''


def main():
    source = Path(sys.argv[1]).read_text()
    header = Path(sys.argv[2]).resolve()

    # The open reads the flag from the fd it keeps, clearing it first.
    opened = function(source, 'aurora_open')
    assert 'self->verify_account = FALSE;' in opened, 'the open does not clear the flag first'
    assert ('self->verify_account = (info.reserved[0] & SEP_BIO_INFO_VERIFY_ACCOUNT) != 0;'
            in opened), 'the open does not record SEP_BIO_INFO_VERIFY_ACCOUNT'
    assert opened.index('self->verify_account = (info') > opened.index('SEP_BIO_GET_INFO'), \
        'the flag is recorded before the open queries the device'

    # The match start must name the chosen account in the verify request, for
    # a verify's one print and for an identify's whole gallery.
    start = function(source, 'aurora_match_start')
    request = start[start.index('memcpy (start.nonce'):start.index('SEP_BIO_VERIFY_START')]
    assert 'aurora_match_account (self, prints, n_prints, &uid)' in request, \
        'the match start no longer chooses the account'
    assert 'start.flags = SEP_BIO_VERIFY_ACCOUNT' in request
    assert 'start.account_uid = uid' in request
    assert 'fpi_device_get_identify_data (device, &gallery)' in request, \
        'an identify does not pass its gallery'
    # The built-in user's zero live count must not end an identify whose
    # gallery is matched in an account's own key bag.
    shortcut = start[start.index('SEP_BIO_INFO_LIVE_COUNT_VALID') - 600:start.index('SEP_BIO_INFO_LIVE_COUNT_VALID')]
    assert 'aurora_match_account (self, (FpPrint **) gallery->pdata, gallery->len' in shortcut, \
        "the zero live-count shortcut applies to an account's gallery"

    code = HARNESS.replace('@ACCOUNT@', function(source, 'aurora_match_account'))
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory)
        (path / 'test.c').write_text(code)
        subprocess.run(['cc', '-std=gnu11', '-Wall', '-Werror', '-I', str(header.parent),
                        'test.c', '-o', 'test'], cwd=path, check=True)
        subprocess.run([str(path / 'test')], check=True)


if __name__ == '__main__':
    main()
