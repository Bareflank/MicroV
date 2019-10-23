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

#include <stdio.h>
#include <stdint.h>
#include <xenctrl.h>
#include <xenstore.h>

/*
 * This is the domid used for the root domain, as defined in
 * microv/vmm/include/xen/domain.h. If that definition changes,
 * this will need to change as well.
 */
#define DOMID_WINPV (DOMID_FIRST_RESERVED - 1)

int main(int argc, char** argv)
{
    xc_interface *xch;
    struct xs_handle *xsh;
    uint64_t xs_pfn;
    uint64_t xs_evtchn;
    int rc;

    xch = xc_interface_open(NULL, NULL, 0);
    if (!xch) {
        printf("winpv: xc_interface_open() failed\n");
        return 1;
    }

    rc = xc_hvm_param_get(xch, DOMID_WINPV, HVM_PARAM_STORE_PFN, &xs_pfn);
    if (rc) {
        printf("winpv: failed to get store pfn of domain 0x%x; rc=%d\n",
               DOMID_WINPV, rc);
        goto close_xc;
    }

    rc = xc_hvm_param_get(xch, DOMID_WINPV, HVM_PARAM_STORE_EVTCHN, &xs_evtchn);
    if (rc) {
        printf("winpv: failed to get store evtchn of domain 0x%x; rc=%d\n",
               DOMID_WINPV, rc);
        goto close_xc;
    }

    rc = 0;
    printf("winpv: xenstore pfn: 0x%lx xenstore evtchn: %lu\n",
           xs_pfn, xs_evtchn);

    xsh = xs_open(0);
    if (!xsh) {
        printf("winpv: xs_open() failed\n");
        rc = 1;
        goto close_xc;
    }

    xs_introduce_domain(xsh, DOMID_WINPV, xs_pfn, xs_evtchn);
    printf("winpv: introduced to xenstore\n");

    xs_close(xsh);

close_xc:
    xc_interface_close(xch);
    return rc;

//    xsh = xs_open(0);
//    if ( !xsh )
//    {
//        fprintf(stderr, "xs_open() failed.\n");
//        return 3;
//    }
//    snprintf(buf, 16, "%d", domid);
//    do_xs_write(xsh, "/tool/xenstored/domid", buf);
//    do_xs_write_dom(xsh, "domid", buf);
//    do_xs_write_dom(xsh, "name", name);
//    snprintf(buf, 16, "%d", memory * 1024);
//    do_xs_write_dom(xsh, "memory/target", buf);
//    if (maxmem)
//        snprintf(buf, 16, "%d", maxmem * 1024);
//    do_xs_write_dom(xsh, "memory/static-max", buf);
//    xs_close(xsh);
//
//    fd = creat(XEN_RUN_DIR "/xenstored.pid", 0666);
//    if ( fd < 0 )
//    {
//        fprintf(stderr, "Creating " XEN_RUN_DIR "/xenstored.pid failed\n");
//        return 3;
//    }
//    rv = snprintf(buf, 16, "domid:%d\n", domid);
//    rv = write(fd, buf, rv);
//    close(fd);
//    if ( rv < 0 )
//    {
//        fprintf(stderr,
//                "Writing domid to " XEN_RUN_DIR "/xenstored.pid failed\n");
//        return 3;
//    }
//
//    return 0;
}
