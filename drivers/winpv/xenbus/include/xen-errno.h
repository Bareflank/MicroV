/* Copyright (c) Citrix Systems Inc.
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, 
 * with or without modification, are permitted provided 
 * that the following conditions are met:
 * 
 * *   Redistributions of source code must retain the above 
 *     copyright notice, this list of conditions and the 
 *     following disclaimer.
 * *   Redistributions in binary form must reproduce the above 
 *     copyright notice, this list of conditions and the 
 *     following disclaimer in the documentation and/or other 
 *     materials provided with the distribution.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND 
 * CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, 
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF 
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE 
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR 
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, 
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, 
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR 
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS 
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, 
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING 
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE 
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF 
 * SUCH DAMAGE.
 */

#ifndef _XEN_ERRNO_H
#define _XEN_ERRNO_H

#include <ntddk.h>

#include <xen/errno.h>

#define EISDIR      21
#define EROFS       30
#define ENOTEMPTY   39

#pragma warning(disable:4127)   // conditional expression is constant

#define ERRNO_TO_STATUS(_errno, _status)                    \
        do {                                                \
            switch (_errno) {                               \
            case EINVAL:                                    \
                _status = STATUS_INVALID_PARAMETER;         \
                break;                                      \
                                                            \
            case EACCES:                                    \
                _status = STATUS_ACCESS_DENIED;             \
                break;                                      \
                                                            \
            case EEXIST:                                    \
                _status = STATUS_OBJECTID_EXISTS;           \
                break;                                      \
                                                            \
            case EISDIR:                                    \
                _status = STATUS_FILE_IS_A_DIRECTORY;       \
                break;                                      \
                                                            \
            case ENOENT:                                    \
                _status = STATUS_OBJECT_NAME_NOT_FOUND;     \
                break;                                      \
                                                            \
            case ENOMEM:                                    \
                _status = STATUS_NO_MEMORY;                 \
                break;                                      \
                                                            \
            case ENOSPC:                                    \
                _status = STATUS_INSUFFICIENT_RESOURCES;    \
                break;                                      \
                                                            \
            case EIO:                                       \
                _status = STATUS_UNEXPECTED_IO_ERROR;       \
                break;                                      \
                                                            \
            case ENOTEMPTY:                                 \
                _status = STATUS_DIRECTORY_NOT_EMPTY;       \
                break;                                      \
                                                            \
            case ENOSYS:                                    \
                _status = STATUS_NOT_IMPLEMENTED;           \
                break;                                      \
                                                            \
            case EROFS:                                     \
                _status = STATUS_MEDIA_WRITE_PROTECTED;     \
                break;                                      \
                                                            \
            case EBUSY:                                     \
                _status = STATUS_PIPE_BUSY;                 \
                break;                                      \
                                                            \
            case EAGAIN:                                    \
                _status = STATUS_RETRY;                     \
                break;                                      \
                                                            \
            case EISCONN:                                   \
                _status = STATUS_PIPE_CONNECTED;            \
                break;                                      \
                                                            \
            case EPERM:                                     \
                _status = STATUS_ACCESS_DENIED;             \
                break;                                      \
                                                            \
            default:                                        \
                _status = STATUS_UNSUCCESSFUL;              \
                break;                                      \
            }                                               \
        } while (FALSE)

#endif  // _XEN_ERRNO_H
