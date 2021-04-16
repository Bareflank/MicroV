/*
 * Copyright (C) 2019 Assured Information Security, Inc.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <efi.h>
#include <efilib.h>

#include <vmm.h>
#include <common.h>

#include <bfdebug.h>
#include <bftypes.h>
#include <bfconstants.h>
#include <bfdriverinterface.h>

#include <xue.h>

extern int g_uefi_boot;
extern int g_enable_winpv;
extern int g_disable_xen_pfd;
extern int g_enable_xue;

extern struct xue g_xue;
extern struct xue_ops g_xue_ops;
struct xue_efi g_xue_efi;

uint64_t g_vcpuid = 0;

struct pmodule_t {
    char *data;
    uint64_t size;
};

uint64_t g_num_pmodules = 0;
struct pmodule_t pmodules[MAX_NUM_MODULES] = {{0}};

static const CHAR16 *opt_disable_xen_pfd = L"--disable-xen-pfd";
static const CHAR16 *opt_enable_winpv = L"--enable-winpv";
static const CHAR16 *opt_disable_winpv = L"--disable-winpv";
static const CHAR16 *opt_pci_pt_class = L"--pci-pt-class";
static const CHAR16 *opt_no_pci_pt = L"--no-pci-pt";
static const CHAR16 *opt_pci_pt = L"--pci-pt";
static const CHAR16 *opt_enable_xue = L"--enable-xue";

#define PCI_PT_CLASS_LIST_SIZE 14
extern uint64_t pci_pt_class_list[PCI_PT_CLASS_LIST_SIZE];
extern uint64_t pci_pt_class_count;

#define NO_PCI_PT_LIST_SIZE 256
extern uint64_t no_pci_pt_list[NO_PCI_PT_LIST_SIZE];
extern uint64_t no_pci_pt_count;

#define PCI_PT_LIST_SIZE 256
extern uint64_t pci_pt_list[PCI_PT_LIST_SIZE];
extern uint64_t pci_pt_count;

#ifndef EFI_BOOT_NEXT
#define EFI_BOOT_NEXT L"\\EFI\\boot\\bootx64.efi"
#endif

#define EFI_CONFIG_FILE_MAX_SIZE (EFI_PAGE_SIZE >> 2)
#ifndef EFI_CONFIG_FILE_PATH
#define EFI_CONFIG_FILE_PATH L"\\EFI\\boot\\bareflank.cfg"
#endif

void unmap_vmm_from_root_domain(void);

static int64_t
ioctl_add_module(const char *file, uint64_t len)
{
    char *buf;
    int64_t ret;

    if (g_num_pmodules >= MAX_NUM_MODULES) {
        BFALERT("IOCTL_ADD_MODULE: too many modules have been loaded\n");
        return BF_IOCTL_FAILURE;
    }

    buf = platform_alloc_rw(len);
    if (buf == NULL) {
        BFALERT("IOCTL_ADD_MODULE: failed to allocate memory for the module\n");
        return BF_IOCTL_FAILURE;
    }

    gBS->CopyMem(buf, (void *)file, len);

    ret = common_add_module(buf, len);
    if (ret != BF_SUCCESS) {
        BFALERT("IOCTL_ADD_MODULE: common_add_module failed: %p - %s\n", (void *)ret, ec_to_str(ret));
        goto failed;
    }

    pmodules[g_num_pmodules].data = buf;
    pmodules[g_num_pmodules].size = len;

    g_num_pmodules++;

    return BF_IOCTL_SUCCESS;

failed:

    platform_free_rw(buf, len);

    BFALERT("IOCTL_ADD_MODULE: failed\n");
    return BF_IOCTL_FAILURE;
}

static long
ioctl_load_vmm(void)
{
    int64_t ret;

    g_uefi_boot = 1;

    ret = common_load_vmm();
    if (ret != BF_SUCCESS) {
        BFALERT("IOCTL_LOAD_VMM: common_load_vmm failed: %p - %s\n", (void *)ret, ec_to_str(ret));
        goto failure;
    }

    return BF_IOCTL_SUCCESS;

failure:

    BFDEBUG("IOCTL_LOAD_VMM: failed\n");
    return BF_IOCTL_FAILURE;
}

static long
ioctl_start_vmm(void)
{
    int64_t ret;

    ret = common_start_vmm();
    if (ret != BF_SUCCESS) {
        BFALERT("IOCTL_START_VMM: common_start_vmm failed: %p - %s\n", (void *)ret, ec_to_str(ret));
        goto failure;
    }

    return BF_IOCTL_SUCCESS;

failure:

    BFDEBUG("IOCTL_START_VMM: failed\n");
    return BF_IOCTL_FAILURE;
}

/* -------------------------------------------------------------------------- */
/* Load / Image                                                               */
/* -------------------------------------------------------------------------- */

/**
 * TODO
 *
 * Instead of loading the OS, we need to actually load a EFI/BOOT/chain.efi
 * file which is the previous EFI/BOOT/boot64.efi. This will allow us to
 * support the different types of loaders that are instealled regardless of
 * which one is actually installed.
 */

static long
load_start_vm(EFI_HANDLE ParentImage)
{
    /**
     * TODO
     *
     * Need to check to see if there are deallocate functions for a lot of
     * these functions as they are returning pointers.
     */

    EFI_STATUS status;

    UINTN i;
    UINTN NumberFileSystemHandles = 0;
    EFI_HANDLE *FileSystemHandles = NULL;

    status =
        gBS->LocateHandleBuffer(
            ByProtocol,
            &gEfiBlockIoProtocolGuid,
            NULL,
            &NumberFileSystemHandles,
            &FileSystemHandles
        );

    if (EFI_ERROR(status)) {
        BFALERT("LocateHandleBuffer failed\n");
        return EFI_ABORTED;
    }

    for(i = 0; i < NumberFileSystemHandles; ++i) {

        EFI_DEVICE_PATH_PROTOCOL *FilePath = NULL;
        EFI_BLOCK_IO *BlkIo = NULL;
        EFI_HANDLE ImageHandle = NULL;
        EFI_LOADED_IMAGE_PROTOCOL *ImageInfo = NULL;

        status =
            gBS->HandleProtocol(
                FileSystemHandles[i],
                &gEfiBlockIoProtocolGuid,
                (VOID**) &BlkIo
            );

        if (EFI_ERROR(status)) {
            continue;
        }

        FilePath = FileDevicePath(FileSystemHandles[i], EFI_BOOT_NEXT);

        status =
            gBS->LoadImage(
                FALSE,
                ParentImage,
                FilePath,
                NULL,
                0,
                &ImageHandle
            );

        gBS->FreePool(FilePath);

        if (EFI_ERROR(status)) {
            continue;
        }

        status =
            gBS->HandleProtocol(
                ImageHandle,
                &gEfiLoadedImageProtocolGuid,
                (VOID **) &ImageInfo
        );

        if (EFI_ERROR(status)) {
            continue;
        }

        if(ImageInfo->ImageCodeType != EfiLoaderCode) {
            continue;
        }

        gBS->StartImage(ImageHandle, NULL, NULL);

        break;
    }

    BFALERT("Unable to locate EFI bootloader\n");
    return EFI_ABORTED;
}

static uint64_t bdf_str_to_uint(const CHAR16 *bdf_str)
{
    UINTN bdf_len = StrLen(bdf_str);

    if (bdf_len != 7) {
        BFALERT("Invalid BDF string size: %u\n", bdf_len);
        BFALERT("  usage: --no-pci-pt BB:DD.F\n");
        return -1ULL;
    }

    CHAR8 bus_str[16];
    CHAR8 dev_str[16];
    CHAR8 fun_str[16];

    ZeroMem(bus_str, 16);
    ZeroMem(dev_str, 16);
    ZeroMem(fun_str, 16);

    CopyMem(bus_str, bdf_str, 4);
    CopyMem(dev_str, (char *)bdf_str + 6, 4);
    CopyMem(fun_str, (char *)bdf_str + 12, 2);

    UINTN bus = xtoi((CHAR16 *)bus_str);
    UINTN dev = xtoi((CHAR16 *)dev_str);
    UINTN fun = xtoi((CHAR16 *)fun_str);

    if (bus > 255 || dev > 31 || fun > 7) {
        BFALERT("BDF out of range: bus=%lx, dev=%lx, fun=%lx\n",
                bus, dev, fun);
        return -1ULL;
    }

    return (bus << 16) | (dev << 11) | (fun << 8);
}

void parse_cmdline(INTN argc, CHAR16 **argv)
{
    INTN i;

    if (argc <= 1) {
        return;
    }

    for (i = 1; i < argc; i++) {
        if (!StrnCmp(opt_enable_xue, argv[i], StrLen(opt_enable_xue) + 1)) {
            BFINFO("Enabling Xue USB Debugger\n");
            g_enable_xue = 1;
            continue;
        }

        if (!StrnCmp(opt_enable_winpv, argv[i], StrLen(opt_enable_winpv) + 1)) {
            BFINFO("Enabling Windows PV\n");
            g_enable_winpv = 1;
            continue;
        }

        if (!StrnCmp(opt_disable_winpv, argv[i], StrLen(opt_disable_winpv) + 1)) {
            BFINFO("Disabling Windows PV\n");
            g_enable_winpv = 0;
            continue;
        }

        if (!StrnCmp(opt_disable_xen_pfd, argv[i], StrLen(opt_disable_xen_pfd) + 1)) {
            BFINFO("Disabling Xen Platform PCI device\n");
            g_disable_xen_pfd = 1;
            continue;
        }

        if (!StrnCmp(opt_pci_pt_class, argv[i], StrLen(opt_pci_pt_class) + 1)) {
            if (i >= argc - 1) {
                BFALERT("Missing class value\n");
                BFALERT("  usage: --pci-pt-class n\n");
                continue;
            }

            CHAR16 *class_str = argv[i + 1];
            UINTN class_len = StrLen(class_str);

            if (class_len != 1 && class_len != 2) {
                BFALERT("Invalid class string size: %u\n", class_len);
                BFALERT("  usage: --pci-pt-class n\n");
                continue;
            }

            UINTN pci_class = Atoi((CHAR16 *) argv[i+1]);
            pci_pt_class_list[pci_pt_class_count] = pci_class;
            pci_pt_class_count++;

            BFINFO("Enabling passthrough for PCI class %ld\n", pci_class);

            i++;
            continue;
        }

        if (!StrnCmp(opt_no_pci_pt, argv[i], StrLen(opt_no_pci_pt) + 1)) {
            if (i >= argc - 1) {
                continue;
            }

            uint64_t bdf = bdf_str_to_uint(argv[i + 1]);
            if (bdf == -1ULL) {
                continue;
            }

            no_pci_pt_list[no_pci_pt_count] = bdf;
            no_pci_pt_count++;

            BFINFO("Disabling passthrough for %02x:%02x.%02x\n",
                (bdf & 0x00FF0000) >> 16,
                (bdf & 0x0000F800) >> 11,
                (bdf & 0x00000700) >> 8);

            i++;
            continue;
        }

        if (!StrnCmp(opt_pci_pt, argv[i], StrLen(opt_pci_pt) + 1)) {
            if (i >= argc - 1) {
                continue;
            }

            uint64_t bdf = bdf_str_to_uint(argv[i + 1]);
            if (bdf == -1ULL) {
                continue;
            }

            pci_pt_list[pci_pt_count] = bdf;
            pci_pt_count++;

            BFINFO("Enabling passthrough for %02x:%02x.%02x\n",
                (bdf & 0x00FF0000) >> 16,
                (bdf & 0x0000F800) >> 11,
                (bdf & 0x00000700) >> 8);

            i++;
            continue;
        }

        BFALERT("Ignoring unknown argument: ");
        Print(L"%s\n", argv[i]);
    }
}

static UINTN read_file(EFI_LOADED_IMAGE *image, const CHAR16 *path, void **buffer)
{
    UINTN size = 0;
    EFI_HANDLE dev_hdl;
    SIMPLE_READ_FILE read_hdl;
    char *buf_tmp = NULL;
    const unsigned buf_size = 512;
    UINTN file_buf_size = 0;
    UINTN read_size = buf_size;

    EFI_DEVICE_PATH *fd_path = FileDevicePath(image->DeviceHandle, (CHAR16 *) path);
    EFI_STATUS status = OpenSimpleReadFile(FALSE, NULL, 0, &fd_path, &dev_hdl, &read_hdl);
    gBS->FreePool(fd_path);

    if (EFI_ERROR(status)) {
        return 0;
    }

    while(read_size == buf_size) {
        read_size = buf_size;
        file_buf_size = size + buf_size;
        buf_tmp = ReallocatePool(buf_tmp, size, file_buf_size);
        status = ReadSimpleReadFile(read_hdl, size, &read_size, buf_tmp + size);

        size += read_size;

        if (EFI_ERROR(status)) {
            BFALERT("OpenSimpleReadFile: failed to read chunk (%r)\n", status);
        }
    }

    buf_tmp = ReallocatePool(buf_tmp, file_buf_size, size);
    *buffer = buf_tmp;

    return size;
}

/**
 * Reads an ascii config file and builds a unicode cmdline string.
 * Lines starting with `#` are ignored and whitespaces are removed.
 * Returns the number of arguments argc and sets argv to an array of arguments
 * with argv[0] set to arg0.
 */
static INTN get_args_from_cfg(EFI_HANDLE hdl, CHAR16 *arg0, CHAR16 **argv[])
{
    EFI_LOADED_IMAGE* image;
    INTN argc = 0;
    UINTN size_ascii = 0;
    char *buf_ascii = NULL;
    char *buf_unicode = NULL;
    char **buf_argv = NULL;
    UINTN i = 0;
    UINTN j = 0;
    BOOLEAN in_comment = FALSE;
    BOOLEAN in_whitespace = TRUE; /* or start */

    gBS->HandleProtocol(hdl, &LoadedImageProtocol, (void**)&image);

    size_ascii = read_file(image, EFI_CONFIG_FILE_PATH, (void**) &buf_ascii);
    if (size_ascii > EFI_CONFIG_FILE_MAX_SIZE) {
        BFDEBUG("get_args_from_cfg: config file size of %d bytes is too large\n", size_ascii);
        return 0;
    }

    /* Build unicode cmdline argc argv: */

    buf_unicode = AllocatePool(size_ascii << 1);
    buf_argv = AllocatePool(size_ascii >> 1);
    buf_argv[argc++] = (char *) arg0;

    for (; i < size_ascii; i++) {
        switch(buf_ascii[i]) {
            case '\n': /* 10 */
                if (in_comment) {
                    in_comment = FALSE;
                }
                /* fall through */
            case '\t': /* 9 */
                /* fall through */
            case ' ': /* 32 */
                in_whitespace = TRUE;
                continue;
            case '!' ... '~': /* 33 ... 126: main ascii chars */
                if (buf_ascii[i] == '#') {
                    in_comment = TRUE;
                    continue;
                }
                break;
            default:
                continue;
        }

        if (in_comment) {
            continue;
        }

        if (in_whitespace) {
            in_whitespace = FALSE;
            buf_unicode[j++] = '\0';
            buf_unicode[j++] = '\0';
            buf_argv[argc++] = &buf_unicode[j];
        }

        buf_unicode[j++] = buf_ascii[i];
        buf_unicode[j++] = '\0';
    }

    buf_unicode[j++] = '\0';
    buf_unicode[j++] = '\0';

    *argv = (CHAR16 **) buf_argv;

    gBS->FreePool(buf_ascii);

    return argc;
}

/* -------------------------------------------------------------------------- */
/* Entry / Exit                                                               */
/* -------------------------------------------------------------------------- */

EFI_STATUS
efi_main(EFI_HANDLE image, EFI_SYSTEM_TABLE *systab)
{
    INTN argc;
    CHAR16 **argv;

    InitializeLib(image, systab);

    if (common_init() != BF_SUCCESS) {
        return EFI_ABORTED;
    }

    g_enable_winpv = 1;

    argc = GetShellArgcArgv(image, &argv);
    if (argc <= 1) {
        /* Read config file */
        argc = get_args_from_cfg(image, argv[0], &argv);
        if (argc > 1) {
            Print(L"[BAREFLANK INFO]: Reading config file from %s\n", EFI_CONFIG_FILE_PATH);
        } else {
            BFDEBUG("No cmdline and no config file!\n");
        }
    }
    parse_cmdline(argc, argv);

#ifdef USE_XUE
    if (g_enable_xue) {
        xue_mset(&g_xue, 0, sizeof(g_xue));
        xue_mset(&g_xue_ops, 0, sizeof(g_xue_ops));
        xue_mset(&g_xue_efi, 0, sizeof(g_xue_efi));

        g_xue_efi.img_hand = image;
        g_xue.sysid = xue_sysid_efi;
        xue_open(&g_xue, &g_xue_ops, &g_xue_efi);
    }
#endif

    ioctl_add_module((char *)vmm, vmm_len);
    ioctl_load_vmm();
    ioctl_start_vmm();

    unmap_vmm_from_root_domain();
    load_start_vm(image);

    return EFI_SUCCESS;
}
