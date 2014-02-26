/*
 *  $Id$
 *
 *  libnet
 *  libnet_build_mmp.c - MMP packet assembler
 *
 *  Copyright (c) 1998 - 2008 Mike D. Schiffman <mike_schiffman@hotmail.com>
 *  All rights reserved.
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
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 */

#if (HAVE_CONFIG_H)
#include "../include/config.h"
#endif
#if (!(_WIN32) || (__CYGWIN__)) 
#include "../include/libnet.h"
#else
#include "../include/win32/libnet.h"
#endif

libnet_ptag_t
libnet_build_mmp(u_int8_t ver, u_int8_t type, u_int16_t flags, 
u_int32_t len, u_int32_t trans_id, u_int8_t *sender_id, u_int8_t *payload, 
u_int32_t payload_s, libnet_t *l, libnet_ptag_t ptag)
{
    u_int32_t n, h;
    libnet_pblock_t *p;
    struct libnet_mmp_hdr mmp_hdr;

    if (l == NULL)
    { 
        return (-1);
    } 
 
    n = LIBNET_MMP_H + payload_s;
    h = 0;

    /*
     *  Find the existing protocol block if a ptag is specified, or create
     *  a new one.
     */
    p = libnet_pblock_probe(l, ptag, n, LIBNET_PBLOCK_MMP_H);
    if (p == NULL)
    {
        return (-1);
    }
    
    memset(&mmp_hdr, 0, sizeof(mmp_hdr));
    mmp_hdr.mmp_version          = ver;
    mmp_hdr.mmp_type             = type;
    mmp_hdr.mmp_flags            = htons(flags);
    mmp_hdr.mmp_length           = htonl(len);
    mmp_hdr.mmp_transaction_id   = htonl(trans_id);
    memcpy(mmp_hdr.mmp_sender_id, sender_id, 12);

    n = libnet_pblock_append(l, p, (u_int8_t *)&mmp_hdr, LIBNET_MMP_H);
    if (n == -1)
    {
        goto bad;
    }

    /* boilerplate payload sanity check / append macro */
    LIBNET_DO_PAYLOAD(l, p);

    return (ptag ? ptag : libnet_pblock_update(l, p, h, LIBNET_PBLOCK_MMP_H));
bad:
    libnet_pblock_delete(l, p);
    return (-1);
}

/* EOF */


libnet_ptag_t
libnet_build_mmp_tlv(u_int16_t type, u_int16_t len, u_int8_t *payload, 
u_int32_t payload_s, libnet_t *l, libnet_ptag_t ptag)
{
    u_int32_t n, h;
    libnet_pblock_t *p;
    struct libnet_mmp_tlv_hdr mmp_tlv_hdr;

    if (l == NULL)
    { 
        return (-1);
    } 
 
    n = LIBNET_MMP_TLV_H + payload_s;
    h = 0;

    /*
     *  Find the existing protocol block if a ptag is specified, or create
     *  a new one.
     */
    p = libnet_pblock_probe(l, ptag, n, LIBNET_PBLOCK_MMP_TLV_H);
    if (p == NULL)
    {
        return (-1);
    }
    
    memset(&mmp_tlv_hdr, 0, sizeof(mmp_tlv_hdr));
    mmp_tlv_hdr.mmp_tlv_type   = htons(type);
    mmp_tlv_hdr.mmp_tlv_length = htons(len);

    n = libnet_pblock_append(l, p, (u_int8_t *)&mmp_tlv_hdr, LIBNET_MMP_TLV_H);
    if (n == -1)
    {
        goto bad;
    }

    /* boilerplate payload sanity check / append macro */
    LIBNET_DO_PAYLOAD(l, p);

    return (ptag ? ptag : libnet_pblock_update(l, p, h, 
            LIBNET_PBLOCK_MMP_TLV_H));
bad:
    libnet_pblock_delete(l, p);
    return (-1);
}

/* EOF */
