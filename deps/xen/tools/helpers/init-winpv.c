//
// Copyright (C) 2019 Assured Information Security, Inc.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

#include <errno.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <xenctrl.h>
#include <xenstore.h>

/*
 * This is the domid used for the root domain, as defined in
 * microv/vmm/include/xen/domain.h. If that definition changes,
 * this will need to change as well.
 */
#define DOMID_WINPV (DOMID_FIRST_RESERVED - 1)
#define ARRAY_SIZE(arr) sizeof(arr)/sizeof(arr[0])
#define VAL_SIZE 64

struct xs_handle *xsh = NULL;
xc_interface *xch = NULL;

static int xs_mkdir_relative(xs_transaction_t t,
                             const char *root,
                             const char *path,
                             struct xs_permissions *perms,
                             int nr_perms)
{
    char buf[XENSTORE_ABS_PATH_MAX];
    const char *slash = "/";

    const size_t slash_size = strlen(slash) + 1;
    const size_t root_size = strlen(root) + 1;
    const size_t path_size = strlen(path) + 1;
    const size_t full_size = root_size + slash_size + path_size;

    if (!xsh) {
        printf("%s: NULL xenstore handle\n", __func__);
        return -EINVAL;
    }

    if (full_size - 2 > sizeof(buf)) {
        return -E2BIG;
    }

    strcpy(buf, root);
    strcat(buf, "/");
    strcat(buf, path);

    xs_mkdir(xsh, t, buf);
    xs_set_permissions(xsh, t, buf, perms, nr_perms);

    return 0;
}

static void xs_mkdir_ro(xs_transaction_t t, const char *path)
{
    /*
     * The first entry in each perm array is the "owner" of the node and
     * provides the default permissions for any other domain not subsequently
     * listed. However Dom0 is able to read/write any node even if it is not
     * listed in the perm array at all.
     *
     * For more information, see tools/xenstore/include/xenstore.h
     */

    struct xs_permissions perms[2];

    perms[0].id = 0;
    perms[0].perms = XS_PERM_NONE;
    perms[1].id = DOMID_WINPV;
    perms[1].perms = XS_PERM_READ;

    xs_mkdir(xsh, t, path);
    xs_set_permissions(xsh, t, path, perms, ARRAY_SIZE(perms));
}

static void xs_mkdir_ro_relative(xs_transaction_t t,
                                 const char *root,
                                 const char *path)
{
    struct xs_permissions perms[2];

    perms[0].id = 0;
    perms[0].perms = XS_PERM_NONE;
    perms[1].id = DOMID_WINPV;
    perms[1].perms = XS_PERM_READ;

    xs_mkdir_relative(t, root, path, perms, ARRAY_SIZE(perms));
}

static void xs_mkdir_rw_relative(xs_transaction_t t,
                                 const char *root,
                                 const char *path)
{
    struct xs_permissions perms[1];

    perms[0].id = DOMID_WINPV;
    perms[0].perms = XS_PERM_NONE;

    xs_mkdir_relative(t, root, path, perms, ARRAY_SIZE(perms));
}

static int xs_write_relative(xs_transaction_t t,
                             const char *root,
                             const char *path,
                             const char *val)
{
    char buf[XENSTORE_ABS_PATH_MAX];
    const char *slash = "/";

    const size_t slash_size = strlen(slash) + 1;
    const size_t root_size = strlen(root) + 1;
    const size_t path_size = strlen(path) + 1;
    const size_t full_size = root_size + slash_size + path_size;

    if (!xsh) {
        printf("%s: NULL xenstore handle\n", __func__);
        return -EINVAL;
    }

    if (full_size - 2 > sizeof(buf)) {
        printf("%s: path too large: %lu\n", __func__, full_size - 2);
        return -E2BIG;
    }

    strcpy(buf, root);
    strcat(buf, "/");
    strcat(buf, path);

    xs_write(xsh, t, buf, val, strlen(val));

    return 0;
}

static int make_xs_dirs(void)
{
    xs_transaction_t t;
    int err, committed;
    char val[VAL_SIZE];
    char *dom_root;

    if (!xsh) {
        printf("%s: NULL xenstore handle\n", __func__);
        return -EINVAL;
    }

    dom_root = xs_get_domain_path(xsh, DOMID_WINPV);
    if (!dom_root) {
        printf("%s: failed to get domain path\n", __func__);
        return -ENODEV;
    }

    t = xs_transaction_start(xsh);

    xs_mkdir_ro(t, dom_root);
    xs_mkdir_ro_relative(t, dom_root, "name");
    xs_mkdir_ro_relative(t, dom_root, "domid");
    xs_mkdir_rw_relative(t, dom_root, "drivers");

    strcpy(val, "winpv");
    xs_write_relative(t, dom_root, "name", val);

    snprintf(val, sizeof(val), "%d", DOMID_WINPV);
    xs_write_relative(t, dom_root, "domid", val);

    committed = xs_transaction_end(xsh, t, 0);
    if (!committed) {
        printf("winpv: transaction failed, errno=%d\n", errno);
        err = errno;
    }

    free(dom_root);
    return err;
}

static int read_xs_params(uint64_t *xs_pfn, uint64_t *xs_chn)
{
    int err = 0;

    if (!xch) {
        printf("%s: NULL xc interface\n", __func__);
        return -EINVAL;
    }

    err = xc_hvm_param_get(xch, DOMID_WINPV, HVM_PARAM_STORE_PFN, xs_pfn);
    if (err) {
        printf("%s: failed to get store pfn, rc=%d\n", __func__, err);
        return err;
    }

    err = xc_hvm_param_get(xch, DOMID_WINPV, HVM_PARAM_STORE_EVTCHN, xs_chn);
    if (err) {
        printf("%s: failed to get store evtchn, rc=%d\n", __func__, err);
        return err;
    }

    if (*xs_pfn == 0) {
        printf("%s: received NULL store pfn\n", __func__);
        return -EINVAL;
    }

    if (*xs_chn == 0) {
        printf("%s: received NULL store evtchn\n", __func__);
        return -EINVAL;
    }

    printf("winpv: xs param: pfn=0x%lx\n", *xs_pfn);
    printf("winpv: xs param: evtchn=%lu\n", *xs_chn);

    return 0;
}

int main(int argc, char** argv)
{
    uint64_t xs_pfn, xs_chn;
    int err = 0;

    xsh = xs_open(0);
    if (!xsh) {
        printf("winpv: xs_open failed\n");
        return -1;
    }

    xch = xc_interface_open(NULL, NULL, 0);
    if (!xch) {
        printf("winpv: xc_interface_open failed\n");
        err = -ENODEV;
        goto close_xs;
    }

    err = make_xs_dirs();
    if (err) {
        printf("winpv: make_xs_dirs failed, rc=%d\n", err);
        goto close_xc;
    }

    err = read_xs_params(&xs_pfn, &xs_chn);
    if (err) {
        printf("winpv: read_xs_params failed, rc=%d\n", err);
        goto close_xc;
    }

    xs_introduce_domain(xsh, DOMID_WINPV, xs_pfn, xs_chn);
    printf("winpv: introduced to xenstore\n");

close_xc:
    xc_interface_close(xch);

close_xs:
    xs_close(xsh);

    return err;
}
