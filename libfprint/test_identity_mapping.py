# SPDX-License-Identifier: MIT
"""Compile the driver's identity mapping with stand-in prints and check that a
touch is credited to the print that holds the matched enclave identity.

The case is a user with two enrolled fingers, left index (identity L) and right
index (identity R), as fprintd files them. The enclave answers R for a right
index touch. Then:
  - a verify of right-index-finger is a match;
  - a verify of left-index-finger is not, because a single-finger verify only
    accepts the requested finger, and the driver says the touch matched another
    enrolled print rather than calling it an unknown identity;
  - an identify over both prints ("any finger", what PAM and GNOME use) picks
    the right index print whatever the gallery order;
  - an identity no print holds matches nothing.
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


def braced(source, first, inside=None):
    """The statement that starts at 'first' (the last one before 'inside',
    when given), up to its matching brace."""
    start = (source.rindex(first, 0, source.index(inside)) if inside
             else source.index(first))
    opening = source.index('{', start)
    depth, end = 1, opening + 1
    while depth:
        depth += (source[end] == '{') - (source[end] == '}')
        end += 1
    return source[start:end]


HARNESS = r'''
#include <assert.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
typedef uint8_t guint8;
typedef unsigned int guint;
typedef size_t gsize;
typedef char gchar;
typedef int gboolean;
#define TRUE 1
#define FALSE 0
#define SEP_BIO_UUID_LEN 16
typedef struct { int domain; int code; const char *message; } GError;
/* A print is its finger and the bytes its fpi-data variant carries. */
typedef struct { int finger; gsize len; guint8 data[32]; int is_ay; } FpPrint;
typedef FpPrint GVariant;
typedef struct { guint len; FpPrint **pdata; } GPtrArray;
#define g_ptr_array_index(a, i) ((a)->pdata[i])
#define g_autoptr(T) T *
#define G_VARIANT_TYPE(s) (s)
#define FP_DEVICE_ERROR 1
#define FP_DEVICE_ERROR_DATA_INVALID 2
static void g_object_get (FpPrint *print, const char *prop, GVariant **out, void *end)
{
  assert (strcmp (prop, "fpi-data") == 0 && end == NULL);
  *out = print->len ? print : NULL;
}
static gboolean g_variant_is_of_type (GVariant *v, const char *type)
{
  return strcmp (type, "ay") == 0 && v->is_ay;
}
static const guint8 *g_variant_get_fixed_array (GVariant *v, gsize *len, gsize size)
{
  assert (size == 1);
  *len = v->len;
  return v->data;
}
static void g_set_error_literal (GError **e, int d, int c, const char *m)
{
  static GError err;
  if (e) { err.domain = d; err.code = c; err.message = m; *e = &err; }
}
static gboolean
@FROM@
static gboolean
@HAS@
/* The driver's identify selection, run on a gallery. */
static FpPrint *identify (GPtrArray *gallery, const guint8 *uuid, FpPrint *matched)
{
  struct { guint8 uuid[SEP_BIO_UUID_LEN]; } res;
  FpPrint *hit = NULL;
  memcpy (res.uuid, uuid, SEP_BIO_UUID_LEN);
  @IDENTIFY@
  return hit;
}
static FpPrint make (int finger, const guint8 *uuid, gsize len)
{
  FpPrint p = { finger, len, { 0 }, 1 };
  memcpy (p.data, uuid, len);
  return p;
}
int main (void)
{
  const guint8 L[16] = { 0x9a, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                         0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
  const guint8 R[16] = { 0x51, 0xcb, 0x1e, 0xc3, 0x0f, 0x0f, 0x4a, 0xbd,
                         0xa6, 0x7e, 0x7c, 0xff, 0x4c, 0xcc, 0x52, 0x6a };
  const guint8 X[16] = { 0x11 };
  FpPrint left = make (2, L, 16), right = make (7, R, 16);
  FpPrint matched = make (0, R, 16);  /* the bare print the enclave reply builds */
  FpPrint *order1[] = { &left, &right }, *order2[] = { &right, &left };
  GPtrArray g1 = { 2, order1 }, g2 = { 2, order2 };
  guint8 out[16];
  GError *err = NULL;

  /* Single-finger verify: only the requested finger's identity counts. */
  assert (aurora_print_has_uuid (&right, R));
  assert (!aurora_print_has_uuid (&left, R));
  assert (aurora_print_has_uuid (&left, L));
  assert (!aurora_print_has_uuid (NULL, R));

  /* Any finger: the gallery print holding the identity, in either order. */
  assert (identify (&g1, R, &matched) == &right);
  assert (identify (&g2, R, &matched) == &right);
  assert (identify (&g1, L, &matched) == &left);
  /* An identity no print holds is no match, never the first print. */
  assert (identify (&g1, X, &matched) == NULL);
  /* No enclave match, no hit. */
  assert (identify (&g1, R, NULL) == NULL);

  /* A print without a 16-byte identity never matches. */
  FpPrint bare = { 7, 0, { 0 }, 1 }, short_id = make (7, R, 8), wrong = make (7, R, 16);
  wrong.is_ay = 0;
  assert (!aurora_print_has_uuid (&bare, R));
  assert (!aurora_print_has_uuid (&short_id, R));
  assert (!aurora_print_has_uuid (&wrong, R));
  assert (!aurora_uuid_from_print (&short_id, out, &err) && err != NULL);
  err = NULL;
  assert (aurora_uuid_from_print (&right, out, &err) && err == NULL);
  assert (memcmp (out, R, 16) == 0);
  return 0;
}
'''


def main():
    source = Path(sys.argv[1]).read_text()

    # The verify path must decide by the requested print's own identity, and
    # name a match of another enrolled print as such, not as a fault.
    verify = braced(source, 'if (action == FPI_DEVICE_ACTION_VERIFY)',
                    'FpPrint *expected = NULL;\n      guint8 expected_uuid')
    assert 'aurora_print_has_uuid (expected, res.uuid)' in verify, \
        'verify no longer compares the requested print by enclave identity'
    assert 'requested print identity is' not in verify, \
        'a touch of another enrolled finger is still reported as a mapping fault'
    assert 'another enrolled print' in verify, \
        'verify does not say the touch matched another enrolled print'
    assert 'FPI_MATCH_FAIL' in verify

    identify = braced(source, 'if (matched != NULL && gallery != NULL)')
    code = (HARNESS.replace('@FROM@', function(source, 'aurora_uuid_from_print'))
            .replace('@HAS@', function(source, 'aurora_print_has_uuid'))
            .replace('@IDENTIFY@', identify))
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory)
        (path / 'test.c').write_text(code)
        subprocess.run(['cc', '-std=gnu11', '-Wall', '-Werror', 'test.c', '-o', 'test'],
                       cwd=path, check=True)
        subprocess.run([str(path / 'test')], check=True)


if __name__ == '__main__':
    main()
