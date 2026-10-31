# SPDX-License-Identifier: MIT
"""Compile real Aurora poll callbacks against fake ioctls and libfprint reports."""
import re
import shlex
import subprocess
import sys
import tempfile
from pathlib import Path


def function(source, name):
    match = re.search(r'^' + name + r' \(', source, re.M)
    if match is None:
        raise AssertionError(f'missing {name}')
    start = source.rfind('\nstatic ', 0, match.start()) + 1
    opening = source.index('{', match.start())
    depth, end = 1, opening + 1
    while depth:
        depth += (source[end] == '{') - (source[end] == '}')
        end += 1
    return source[start:end]


HARNESS = r'''
#include <glib-object.h>
#include <assert.h>
#include <stdarg.h>
#include <string.h>
#include <time.h>
#include "apple-sep.h"
_Static_assert(sizeof(struct sep_bio_enrol_poll) == 40, "enrol poll ABI");
_Static_assert(sizeof(struct sep_bio_verify_poll) == 72, "verify poll ABI");
@STATUSES@
typedef GObject FpPrint;
typedef struct {
    guint watch_id, enroll_last_reported_stage, enroll_last_guidance;
    guint8 nonce[SEP_BIO_NONCE_LEN];
    gboolean nonce_valid;
} FpDevice;
typedef FpDevice FpiDeviceAurora;
typedef int FpiDeviceAction;
typedef int FpFingerStatusFlags;
#define FP_DEVICE(p) ((FpDevice *)(p))
#define FPI_DEVICE_AURORA(p) ((FpiDeviceAurora *)(p))
#define FP_DEVICE_RETRY (g_quark_from_static_string("retry"))
#define FP_DEVICE_ERROR (g_quark_from_static_string("error"))
#define FP_DEVICE_RETRY_GENERAL 0
#define FP_DEVICE_RETRY_REMOVE_FINGER 3
#define FP_DEVICE_ERROR_GENERAL 0
#define FP_FINGER_STATUS_NONE 0
#define FP_FINGER_STATUS_NEEDED 1
#define FP_FINGER_STATUS_PRESENT 2
#define FPI_MATCH_ERROR 0
#define FPI_MATCH_SUCCESS 1
#define FPI_MATCH_FAIL 2
#define FPI_DEVICE_ACTION_VERIFY 1
#define FPI_DEVICE_ACTION_IDENTIFY 2
#define FPI_PRINT_RAW 1
#define fp_dbg(...) ((void)0)
static FpiDeviceAction action;
static struct sep_bio_verify_poll verify_poll;
static struct sep_bio_enrol_poll enrol_poll;
static FpPrint *expected;
static GPtrArray *gallery;
static int reports, completes, match_result, finger_status, retry_code, passed;
static guint progress_stage;
static gboolean fail_ioctl;
static GError *last_error;
static GError *fpi_device_retry_new_msg(int code, const char *format, ...) {
    va_list ap; va_start(ap, format);
    GError *error = g_error_new_valist(FP_DEVICE_RETRY, code, format, ap);
    va_end(ap); return error;
}
static GError *fpi_device_error_new_msg(int code, const char *format, ...) {
    va_list ap; va_start(ap, format);
    GError *error = g_error_new_valist(FP_DEVICE_ERROR, code, format, ap);
    va_end(ap); return error;
}
static GError *fpi_device_error_new(int code) { return g_error_new_literal(FP_DEVICE_ERROR,code,"failed"); }
static gboolean aurora_ioctl(FpiDeviceAurora *self, unsigned long req, void *arg, GError **error) {
    (void)self;
    if (fail_ioctl) { *error=fpi_device_error_new(0); return FALSE; }
    if (req == SEP_BIO_VERIFY_POLL) memcpy(arg,&verify_poll,sizeof verify_poll);
    else { assert(req == SEP_BIO_ENROL_POLL); memcpy(arg,&enrol_poll,sizeof enrol_poll); }
    return TRUE;
}
static void fpi_device_report_finger_status(FpDevice *d, int status) { (void)d; finger_status=status; }
static int fpi_device_get_current_action(FpDevice *d) { (void)d; return action; }
static void fpi_device_get_verify_data(FpDevice *d, FpPrint **p) { (void)d; *p=expected; }
static void fpi_device_get_identify_data(FpDevice *d, GPtrArray **p) { (void)d; *p=gallery; }
static void fpi_device_get_enroll_data(FpDevice *d, FpPrint **p) { (void)d; *p=NULL; }
static void fpi_print_set_type(FpPrint *p, int type) { (void)p;(void)type; }
static void fpi_print_set_device_stored(FpPrint *p, gboolean stored) { (void)p;(void)stored; }
static gboolean aurora_print_has_uuid(FpPrint *p, const guint8 *uuid) { return p && uuid[0]==0xa5; }
static gboolean aurora_uuid_from_print(FpPrint *p, guint8 *uuid, GError **error) {
    (void)error; memset(uuid,0xa5,SEP_BIO_UUID_LEN); return p!=NULL;
}
static void aurora_uuid_hex(const guint8 *uuid, gchar *out) { (void)uuid; memset(out,'a',32);out[32]=0; }
static FpPrint *aurora_print_from_uuid(FpiDeviceAurora *s, const guint8 *u, GError **e) {
    (void)s;(void)u;(void)e; return g_object_new(G_TYPE_OBJECT,NULL);
}
static void report(GError *error) {
    reports++; assert(reports==1);
    g_clear_error(&last_error); last_error=error;
    retry_code=error?error->code:-1;
}
static void complete(GError *error) {
    completes++; assert(completes==1);
    if (error) { assert(error->domain!=FP_DEVICE_RETRY); g_clear_error(&last_error); last_error=error; }
}
static void fpi_device_verify_report(FpDevice *d,int result,FpPrint *p,GError *e) {
    (void)d;match_result=result;report(e);if(p)g_object_unref(p);
}
static void fpi_device_identify_report(FpDevice *d,FpPrint *hit,FpPrint *p,GError *e) {
    (void)d;match_result=hit?FPI_MATCH_SUCCESS:FPI_MATCH_FAIL;report(e);if(p)g_object_unref(p);
}
static void fpi_device_verify_complete(FpDevice *d,GError *e) { (void)d;complete(e); }
static void fpi_device_identify_complete(FpDevice *d,GError *e) { (void)d;complete(e); }
static void fpi_device_enroll_complete(FpDevice *d,FpPrint *p,GError *e) { (void)d;(void)p;complete(e); }
static void fpi_device_enroll_progress(FpDevice *d,guint stage,FpPrint *p,GError *e) {
    (void)d;assert(p==NULL);progress_stage=stage;
    if(e) { assert(e->domain==FP_DEVICE_RETRY);retry_code=e->code;reports++;g_error_free(e); }
    else passed++;
}
@FUNCTIONS@
static void reset(FpDevice *d) {
    memset(d,0,sizeof *d);d->watch_id=42;d->nonce_valid=TRUE;memset(d->nonce,1,sizeof d->nonce);
    memset(&verify_poll,0,sizeof verify_poll);memset(&enrol_poll,0,sizeof enrol_poll);
    reports=completes=passed=0;match_result=retry_code=-1;progress_stage=0;fail_ioctl=FALSE;
    g_clear_error(&last_error);
}
int main(void) {
    FpDevice d;
    expected=g_object_new(G_TYPE_OBJECT,NULL);gallery=g_ptr_array_new();g_ptr_array_add(gallery,expected);
    for(action=FPI_DEVICE_ACTION_VERIFY;action<=FPI_DEVICE_ACTION_IDENTIFY;action++) {
        reset(&d);verify_poll.state=SEP_BIO_STATE_PENDING;verify_poll.guidance=SEP_BIO_GUIDANCE_REMOVE_FINGER;
        assert(aurora_verify_ready(0,0,&d)==G_SOURCE_CONTINUE);
        assert(!reports&&!completes&&finger_status==FP_FINGER_STATUS_PRESENT&&d.nonce_valid);
        for(guint status=5;status<=8;status+=3) {
            reset(&d);verify_poll.state=SEP_BIO_STATE_FAILED;verify_poll.result=SEP_BIO_NOT_COMPARED;verify_poll.status=status;
            assert(aurora_verify_ready(0,0,&d)==G_SOURCE_REMOVE);
            assert(reports==1&&completes==1&&last_error->domain==FP_DEVICE_RETRY);
            assert(retry_code==(status==8?FP_DEVICE_RETRY_REMOVE_FINGER:FP_DEVICE_RETRY_GENERAL));
            assert(!d.nonce_valid&&d.watch_id==0&&finger_status==FP_FINGER_STATUS_NONE);
            for(guint i=0;i<sizeof d.nonce;i++)assert(d.nonce[i]==0);
        }
        reset(&d);verify_poll.state=SEP_BIO_STATE_DONE;verify_poll.result=SEP_BIO_NO_MATCH;
        assert(aurora_verify_ready(0,0,&d)==G_SOURCE_REMOVE);
        assert(reports==1&&completes==1&&!last_error&&match_result==FPI_MATCH_FAIL);
        reset(&d);verify_poll.state=SEP_BIO_STATE_FAILED;verify_poll.result=SEP_BIO_NOT_COMPARED;verify_poll.status=1;
        aurora_verify_ready(0,0,&d);assert(!reports&&completes==1&&last_error->domain==FP_DEVICE_ERROR);
        reset(&d);fail_ioctl=TRUE;aurora_verify_ready(0,0,&d);
        assert(!reports&&completes==1&&last_error->domain==FP_DEVICE_ERROR&&!d.nonce_valid&&d.watch_id==0);
        reset(&d);verify_poll.state=SEP_BIO_STATE_DONE;verify_poll.result=SEP_BIO_MATCH;
        memset(verify_poll.uuid,0xa5,sizeof verify_poll.uuid);verify_poll.token[0]=1;verify_poll.deadline_ns=G_MAXUINT64;
        aurora_verify_ready(0,0,&d);assert(reports==1&&completes==1&&!last_error&&match_result==FPI_MATCH_SUCCESS);
    }
    reset(&d);enrol_poll.state=SEP_BIO_STATE_PENDING;enrol_poll.guidance=SEP_BIO_GUIDANCE_REMOVE_FINGER;
    for(int i=0;i<3;i++)assert(aurora_enrol_ready(0,0,&d)==G_SOURCE_CONTINUE);
    assert(reports==1&&!passed&&!completes&&progress_stage==0&&retry_code==FP_DEVICE_RETRY_REMOVE_FINGER);
    assert(finger_status==FP_FINGER_STATUS_PRESENT);
    enrol_poll.guidance=SEP_BIO_GUIDANCE_PLACE;aurora_enrol_ready(0,0,&d);
    assert(reports==1&&!passed&&finger_status==FP_FINGER_STATUS_NEEDED);
    enrol_poll.state=SEP_BIO_STATE_PROGRESS;enrol_poll.stage=1;enrol_poll.guidance=SEP_BIO_GUIDANCE_HOLD_STILL;
    aurora_enrol_ready(0,0,&d);assert(passed==1&&d.enroll_last_reported_stage==1);
    enrol_poll.state=SEP_BIO_STATE_PENDING;enrol_poll.guidance=SEP_BIO_GUIDANCE_REMOVE_FINGER;
    aurora_enrol_ready(0,0,&d);assert(reports==2&&passed==1&&progress_stage==1&&!completes);
    enrol_poll.guidance=SEP_BIO_GUIDANCE_HOLD_STILL;enrol_poll.status=SEP_BIO_STATUS_RETRY;
    aurora_enrol_ready(0,0,&d);assert(reports==3&&passed==1&&retry_code==FP_DEVICE_RETRY_GENERAL);
    g_object_unref(expected);g_ptr_array_unref(gallery);g_clear_error(&last_error);
    return 0;
}
'''


def main():
    source = Path(sys.argv[1]).read_text()
    header = Path(sys.argv[2]).resolve()
    statuses = source[source.index('#ifndef SEP_BIO_STATUS_REJECTED'):source.index('struct _FpiDeviceAurora')]
    names = ('aurora_retry_new', 'aurora_report_guidance', 'aurora_status_reason', 'aurora_failure_new',
             'aurora_not_compared_new', 'aurora_result_is_match', 'aurora_enrol_ready', 'aurora_verify_ready')
    code = HARNESS.replace('@STATUSES@', statuses).replace('@FUNCTIONS@', '\n'.join(function(source, name) for name in names))
    flags = shlex.split(subprocess.check_output(['pkg-config', '--cflags', '--libs', 'gobject-2.0'], text=True))
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory)
        (path / 'test.c').write_text(code)
        for legacy in (False, True):
            header_text = header.read_text()
            if legacy:
                header_text = re.sub(r'^#define SEP_BIO_(GUIDANCE|STATUS)_REMOVE_FINGER[^\n]*\n', '', header_text, flags=re.M)
            (path / 'apple-sep.h').write_text(header_text)
            subprocess.run(['cc', '-std=c11', '-D_POSIX_C_SOURCE=200809L', '-Wall', '-Werror', '-Wno-unused-function',
                            '-I' + str(path), 'test.c', '-o', 'test', *flags], cwd=path, check=True)
            subprocess.run([str(path / 'test')], check=True)
        print('fresh-contact callbacks: current and legacy headers passed')


if __name__ == '__main__':
    main()
