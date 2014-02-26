/*
 *  $Id: libnet_build_tcp.c,v 1.11 2004/01/28 19:45:00 mike Exp $
 *
 *  libnet
 *  libnet_build_tcp.c - TCP packet assembler
 *
 *  Copyright (c) 1998 - 2004 Mike D. Schiffman <mike@infonexus.com>
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
libnet_build_tcp(u_int16_t sp, u_int16_t dp, u_int32_t seq, u_int32_t ack,
u_int8_t control, u_int16_t win, u_int16_t sum, u_int16_t urg, u_int16_t len,
u_int8_t *payload, u_int32_t payload_s, libnet_t *l, libnet_ptag_t ptag)
{
    int n, offset;
    u_int32_t i, j;
    libnet_pblock_t *p, *p_data, *p_temp;
    libnet_ptag_t ptag_hold, ptag_data;
    struct libnet_tcp_hdr tcp_hdr;
    struct libnet_ipv4_hdr *ip_hdr;

    if (l == NULL)
    { 
        return (-1);
    } 

    ptag_data = 0;                      /* for possible options */

    /*
     *  Find the existing protocol block if a ptag is specified, or create
     *  a new one.
     */
    p = libnet_pblock_probe(l, ptag, LIBNET_TCP_H, LIBNET_PBLOCK_TCP_H);
    if (p == NULL)
    {
        return (-1);
    }

    memset(&tcp_hdr, 0, sizeof(tcp_hdr));
    tcp_hdr.th_sport   = htons(sp);    /* source port */
    tcp_hdr.th_dport   = htons(dp);    /* destination port */
    tcp_hdr.th_seq     = htonl(seq);   /* sequence number */
    tcp_hdr.th_ack     = htonl(ack);   /* acknowledgement number */
    tcp_hdr.th_flags   = control;      /* control flags */
    tcp_hdr.th_x2      = 0;            /* UNUSED */
    tcp_hdr.th_off     = 5;            /* 20 byte header */

    /* check to see if there are TCP options to include */
    if (p->prev)
    {
        p_temp = p->prev;
        while ((p_temp->prev) && (p_temp->type != LIBNET_PBLOCK_TCPO_H))
        {
            p_temp = p_temp->prev;
        }
        if (p_temp->type == LIBNET_PBLOCK_TCPO_H)
        {
            /*
             *  Count up number of 32-bit words in options list, padding if
             *  neccessary.
             */
            for (i = 0, j = 0; i < p_temp->b_len; i++)
            {
                (i % 4) ? j : j++;
            }
            tcp_hdr.th_off += j;
        }
    }

    tcp_hdr.th_win     = htons(win);   /* window size */
    tcp_hdr.th_sum     = (sum ? htons(sum) : 0);   /* checksum */ 
    tcp_hdr.th_urp     = htons(urg);          /* urgent pointer */

    n = libnet_pblock_append(l, p, (u_int8_t *)&tcp_hdr, LIBNET_TCP_H);
    if (n == -1)
    {
        goto bad;
    }

    ptag_hold = ptag;
    if (ptag == LIBNET_PTAG_INITIALIZER)
    {
        ptag = libnet_pblock_update(l, p, len, LIBNET_PBLOCK_TCP_H);
    }

    /* find and set the appropriate ptag, or else use the default of 0 */
    offset = payload_s;
    if (ptag_hold && p->prev)
    {
        p_temp = p->prev;
        while (p_temp->prev &&
              (p_temp->type != LIBNET_PBLOCK_TCPDATA) &&
              (p_temp->type != LIBNET_PBLOCK_TCP_H))
        {
           p_temp = p_temp->prev;
        }

        if (p_temp->type == LIBNET_PBLOCK_TCPDATA)
        {
            ptag_data = p_temp->ptag;
            offset -=  p_temp->b_len;
            p->h_len += offset;
        }
        else
        {
            snprintf(l->err_buf, LIBNET_ERRBUF_SIZE,
				    "%s(): TCP data pblock not found\n", __func__);
        }
     }

    /* update ip_len if present */
    if (ptag_hold && p->next)
    {
        p_temp = p->next;
        while (p_temp->next && (p_temp->type != LIBNET_PBLOCK_IPV4_H))
        {
            p_temp = p_temp->next;
        }
        if (p_temp->type == LIBNET_PBLOCK_IPV4_H)
        {
            ip_hdr = (struct libnet_ipv4_hdr *)p_temp->buf;
            n = ntohs(ip_hdr->ip_len) + offset;
            ip_hdr->ip_len = htons(n);
        }
    }

    if ((payload && !payload_s) || (!payload && payload_s))
    {
        snprintf(l->err_buf, LIBNET_ERRBUF_SIZE,
			    "%s(): payload inconsistency\n", __func__);
        goto bad;
    }

    /* if there is a payload, add it in the context */
    if (payload && payload_s)
    {
        /* update ptag_data with the new payload */
        p_data = libnet_pblock_probe(l, ptag_data, payload_s,
                LIBNET_PBLOCK_TCPDATA);
        if (p_data == NULL) 
        {
            return (-1);
        }

        if (libnet_pblock_append(l, p_data, payload, payload_s) == -1)
        {
            goto bad;
        }

        if (ptag_data == LIBNET_PTAG_INITIALIZER)
        {
            if (p_data->prev->type == LIBNET_PBLOCK_TCP_H)
            {
                libnet_pblock_update(l, p_data, payload_s,
                        LIBNET_PBLOCK_TCPDATA);
                /* swap pblocks to correct the protocol order */
                libnet_pblock_swap(l, p->ptag, p_data->ptag);
            }
            else
            {
                /* update without setting this as the final pblock */
                p_data->type  =  LIBNET_PBLOCK_TCPDATA;
                p_data->ptag  =  ++(l->ptag_state);
                p_data->h_len =  payload_s;

                /* Adjust h_len for checksum. */
                p->h_len += payload_s;

                /* data was added after the initial construction */
                for (p_temp = l->protocol_blocks;
                        p_temp->type == LIBNET_PBLOCK_TCP_H ||
                        p_temp->type == LIBNET_PBLOCK_TCPO_H;
                        p_temp = p_temp->next)
                {
                    libnet_pblock_insert_before(l, p_temp->ptag, p_data->ptag);
                    break;
                }
                /* The end block needs to have its next pointer cleared. */
                l->pblock_end->next = NULL;
            }

            if (p_data->prev && p_data->prev->type == LIBNET_PBLOCK_TCPO_H)
            {
                libnet_pblock_swap(l, p_data->prev->ptag, p_data->ptag);
            }
        }
    }
    else
    {
        p_data = libnet_pblock_find(l, ptag_data);
        if (p_data) 
        {
            libnet_pblock_delete(l, p_data);
        }
    }

    if (sum == 0)
    {
        /*
         *  If checksum is zero, by default libnet will compute a checksum
         *  for the user.  The programmer can override this by calling
         *  libnet_toggle_checksum(l, ptag, 1);
         */
        libnet_pblock_setflags(p, LIBNET_PBLOCK_DO_CHECKSUM);
    }
    return (ptag);
bad:
    libnet_pblock_delete(l, p);
    return (-1);
}


libnet_ptag_t
libnet_build_tcp_options(u_int8_t *options, u_int32_t options_s, libnet_t *l, 
libnet_ptag_t ptag)
{
    int offset, underflow;
    u_int32_t i, j, n, adj_size;
    libnet_pblock_t *p, *p_temp;
    struct libnet_ipv4_hdr *ip_hdr;
    struct libnet_tcp_hdr *tcp_hdr;

    if (l == NULL)
    { 
        return (-1);
    }

    underflow = 0;
    offset = 0;

    /* check options list size */
    if (options_s > LIBNET_MAXOPTION_SIZE)
    {
        snprintf(l->err_buf, LIBNET_ERRBUF_SIZE,
            "%s(): options list is too large %d\n", __func__, options_s);
        return (-1);
    }

    adj_size = options_s;
    if (adj_size % 4)
    {
        /* size of memory block with padding */
        adj_size += 4 - (options_s % 4);
    }

    /* if this pblock already exists, determine if there is a size diff */
    if (ptag)
    {
        p_temp = libnet_pblock_find(l, ptag);
        if (p_temp)
        {
            if (adj_size >= p_temp->b_len)
            {
                offset = adj_size - p_temp->b_len;
            }
            else
            {
                offset = p_temp->b_len - adj_size;
                underflow = 1;
            }
        }
    }

    /*
     *  Find the existing protocol block if a ptag is specified, or create
     *  a new one.
     */
    p = libnet_pblock_probe(l, ptag, adj_size, LIBNET_PBLOCK_TCPO_H);
    if (p == NULL)
    {
        return (-1);
    }
	
    n = libnet_pblock_append(l, p, options, adj_size);
    if (n == -1)
    {
        goto bad;
    }
	
    if (ptag && p->next)
    {
        p_temp = p->next;
        while ((p_temp->next) && (p_temp->type != LIBNET_PBLOCK_TCP_H))
        {
           p_temp = p_temp->next;
        }
        if (p_temp->type == LIBNET_PBLOCK_TCP_H)
        {
            /*
             *  Count up number of 32-bit words in options list, padding if
             *  neccessary.
             */
            for (i = 0, j = 0; i < p->b_len; i++)
            {
                (i % 4) ? j : j++;
            }
            tcp_hdr = (struct libnet_tcp_hdr *)p_temp->buf;
            tcp_hdr->th_off = j + 5;
            if (!underflow)
            {
                p_temp->h_len += offset;
            }
            else
            {
                p_temp->h_len -= offset;
            }
        }
        while ((p_temp->next) && (p_temp->type != LIBNET_PBLOCK_IPV4_H))
        {
            p_temp = p_temp->next;
        }
        if (p_temp->type == LIBNET_PBLOCK_IPV4_H)
        {
            ip_hdr = (struct libnet_ipv4_hdr *)p_temp->buf;
            if (!underflow)
            {
                ip_hdr->ip_len += htons(offset);
            }
            else
            {
                ip_hdr->ip_len -= htons(offset);
            }
        }
    }

    return (ptag ? ptag : libnet_pblock_update(l, p, adj_size,
            LIBNET_PBLOCK_TCPO_H));
bad:
    libnet_pblock_delete(l, p);
    return (-1);
}

/* EOF */
