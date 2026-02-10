/*
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright 2018-2026 SUSE LLC
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef _WIN_CMP_STRTOL_H
#define _WIN_CMP_STRTOL_H

#include <win_stdint.h>

/* only support 10 and 16 based */
static __inline xen_ulong_t
cmp_strtoul(const char *ptr, char **endptr, int radix)
{
    unsigned char ch;
    unsigned int i = 0;
    xen_ulong_t res = 0;
    const char *p;
    int valid = 1;

    if (ptr == NULL) {
        return 0;
    }

    for (p = ptr; *p != '\0' && valid; p++) {
        ch = *p;
        switch (ch) {
        case '0':
        case '1':
        case '2':
        case '3':
        case '4':
        case '5':
        case '6':
        case '7':
        case '8':
        case '9':
            i = ch - '0';
            break;

        case 'A':
        case 'B':
        case 'C':
        case 'D':
        case 'E':
        case 'F':
            if (radix == 16) {
                i = ch - 'A' + 10;
            } else {
                valid = 0;
                p--;
            }
            break;

        case 'a':
        case 'b':
        case 'c':
        case 'd':
        case 'e':
        case 'f':
            if (radix == 16) {
                i = ch - 'a' + 10;
            } else {
                valid = 0;
                p--;
            }
            break;

        default:
            valid = 0;
            p--;
            break;
        }
        if (valid) {
            res = res * radix + i;
        }
    }
    if (endptr) {
        *endptr = (char *) p;
    }
    return res;
}

static __inline uint64_t
cmp_strtou64(const char *ptr, char **endptr, int radix)
{
    unsigned char ch;
    unsigned int i = 0;
    uint64_t res = 0;
    const char *p;
    int valid = 1;

    if (ptr == NULL) {
        return 0;
    }

    for (p = ptr; *p != '\0' && valid; p++) {
        ch = *p;
        switch (ch) {
        case '0':
        case '1':
        case '2':
        case '3':
        case '4':
        case '5':
        case '6':
        case '7':
        case '8':
        case '9':
            i = ch - '0';
            break;

        case 'A':
        case 'B':
        case 'C':
        case 'D':
        case 'E':
        case 'F':
            if (radix == 16) {
                i = ch - 'A' + 10;
            } else {
                valid = 0;
                p--;
            }
            break;

        case 'a':
        case 'b':
        case 'c':
        case 'd':
        case 'e':
        case 'f':
            if (radix == 16) {
                i = ch - 'a' + 10;
            } else {
                valid = 0;
                p--;
            }
            break;

        default:
            valid = 0;
            p--;
            break;
        }
        if (valid) {
            res = res * radix + i;
        }
    }
    if (endptr) {
        *endptr = (char *) p;
    }
    return res;
}

#endif
