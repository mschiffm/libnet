dnl $Id: acinclude.m4,v 1.3 2004/01/15 23:53:06 mike Exp $
dnl
dnl Libnet specific autoconf macros
dnl Copyright (c) 1998 - 2004 Mike D. Schiffman <mike@infonexus.com>
dnl All rights reserved.
dnl

dnl
dnl Check for the Linux /proc filesystem
dnl
dnl usage:      AC_LIBNET_LINUX_PROCFS
dnl results:    HAVE_LINUX_PROCFS
dnl
AC_DEFUN([AC_LIBNET_LINUX_PROCFS],
    [AC_MSG_CHECKING(for Linux proc filesystem)
    AC_CACHE_VAL(ac_cv_libnet_linux_procfs,
        if test "x`cat /proc/sys/kernel/ostype 2>&-`" = "xLinux" ; then
            ac_cv_libnet_linux_procfs=yes
        else
            ac_cv_libnet_linux_procfs=no
        fi)
    AC_MSG_RESULT($ac_cv_libnet_linux_procfs)
    if test $ac_cv_libnet_linux_procfs = yes ; then
        AC_DEFINE(HAVE_LINUX_PROCFS, 1,
                  [Define if you have the Linux /proc filesystem.])
    fi])

dnl
dnl Checks to see if this linux kernel has a working PF_PACKET
dnl
dnl usage:
dnl
dnl     AC_LIBNET_CHECK_PF_PACKET
dnl
dnl results:
dnl
dnl     HAVE_PACKET_SOCKET (DEFINED)
dnl

AC_DEFUN([AC_LIBNET_CHECK_PF_PACKET],
[
    AC_MSG_CHECKING(for packet socket (PF_SOCKET))
    AC_CACHE_VAL(ac_libnet_have_packet_socket,

        [case "$target_os" in

        linux)
                ac_libnet_have_packet_socket = no
                ;;
        *)

    cat > pf_packet-test.c << EOF
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <features.h>    /* for the glibc version number */
#if __GLIBC__ >= 2 && __GLIBC_MINOR >= 1
#include <netpacket/packet.h>
#include <net/ethernet.h>     /* the L2 protocols */
#else
#include <asm/types.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>   /* The L2 protocols */
#endif
 
#ifndef SOL_PACKET
#define SOL_PACKET 263
#endif  /* SOL_PACKET */
 
int
main(int argc, char **argv)
{
    int fd;
 
    fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (fd == -1)
    {
        if (errno == EPERM)
        {
            /* user's UID != 0 */
            printf("probably");
            exit (EXIT_FAILURE);
        }
        printf("no");
        exit (EXIT_FAILURE);
    }
    printf("yes");
    exit (EXIT_SUCCESS);
}
EOF
    ${CC-cc} -o pf_packet-test $CFLAGS pf_packet-test.c >/dev/null 2>&1

    # Oopz 4.3 BSD doesn't have this.  Sorry.
    if test ! -x ./pf_packet-test ; then
        ac_libnet_have_packet_socket=choked
    else
        ac_libnet_have_packet_socket=`./pf_packet-test`;
    fi
    if test $ac_libnet_have_packet_socket = choked; then
        AC_MSG_RESULT(test program compile choked... assuming no)
    elif test $ac_libnet_have_packet_socket = yes; then
        AC_MSG_RESULT(yes)
    elif test $ac_libnet_have_packet_socket = probably; then
        AC_MSG_RESULT(test program got EPERM... assuming yes)
    elif test $ac_libnet_have_packet_socket = no; then
        AC_MSG_RESULT(no)
    fi

    rm -f pf_packet-test* core core.pf_packet-test
    ;;
    esac])

    if test $ac_libnet_have_packet_socket = yes -o $ac_libnet_have_packet_socket = probably; then
        AC_DEFINE(HAVE_PACKET_SOCKET, 1,
          [Define if we're running on a Linux system with PF_PACKET sockets.])
    fi
])

dnl
dnl Looks for a previous libnet version and attempts to determine which verion
dnl it is.  Version 0.8 was the first version that actually knew internally
dnl what version it was.
dnl
dnl usage:
dnl
dnl     AC_LIBNET_CHECK_LIBNET_VERSION
dnl
dnl results:
dnl
dnl
dnl

AC_DEFUN([AC_LIBNET_CHECK_LIBNET_VER],
[
    AC_CHECK_LIB(net, libnet_build_ip, AC_MSG_CHECKING(version) \

changequote(<<, >>)dnl
    if [[ ! -f $LIB_PREFIX/libnet.a ]] ; then
changequote([, ])dnl
        AC_MSG_RESULT($LIB_PREFIX/libnet.a doesn't exist)
        AC_MSG_RESULT(previous libnet install lives elsewhere, you should probably find it)
    else
        __LIBNET_VERSION=`strings $LIB_PREFIX/libnet.a | grep "libnet version"\
                | cut -f3 -d" "`;\
        if test -z "$__LIBNET_VERSION"; then
            AC_MSG_RESULT(<0.8)
        else
            AC_MSG_RESULT($__LIBNET_VERSION)
        fi
    fi\
    )
])


dnl
dnl Checks to see if this linux kernel uses ip_sum or ip_csum
dnl (Pulled from queso)
dnl
dnl usage:
dnl
dnl     AC_LIBNET_CHECK_IP_CSUM
dnl
dnl results:
dnl
dnl     HAVE_STRUCT_IP_CSUM (DEFINED)
dnl

AC_DEFUN([AC_LIBNET_CHECK_IP_CSUM],
[
    AC_MSG_CHECKING([struct ip contains ip_csum])
    AC_TRY_COMPILE([
        #define __BSD_SOURCE
        #define _BSD_SOURCE
        #include <sys/types.h>
        #include <netinet/in.h>
        #include <netinet/in_systm.h>
        #include <netinet/ip.h>],
        [
            struct ip ip;
            ip.ip_csum = 0;
        ],
        [AC_MSG_RESULT(yes);
        AC_DEFINE(HAVE_STRUCT_IP_CSUM)],
        [AC_MSG_RESULT(no);
    ])
])

dnl
dnl Checks to see if unaligned memory accesses fail
dnl (Pulled from libpcap)
dnl
dnl usage:
dnl
dnl     AC_LBL_UNALIGNED_ACCESS
dnl
dnl results:
dnl
dnl     LBL_ALIGN (DEFINED)
dnl

AC_DEFUN([AC_LBL_UNALIGNED_ACCESS],
    [AC_MSG_CHECKING(if unaligned accesses fail)
    AC_CACHE_VAL(ac_cv_lbl_unaligned_fail,
        [case "$target_cpu" in

        alpha|hp*|mips|sparc)
                ac_cv_lbl_unaligned_fail=yes
                ;;

        *)
                cat >conftest.c <<EOF
#                   include <sys/types.h>
#                   include <sys/wait.h>
#                   include <stdio.h>
                    unsigned char a[[5]] = { 1, 2, 3, 4, 5 };
                    main()
                    {
                        unsigned int i;
                        pid_t pid;
                        int status;
                        /* avoid "core dumped" message */
                        pid = fork();
                        if (pid <  0)
                        {
                            exit(2);
                        }
                        if (pid > 0)
                        {
                            /* parent */
                            pid = waitpid(pid, &status, 0);
                            if (pid < 0)
                            {
                                exit(3);
                            }
                            exit(!WIFEXITED(status));
                        }
                        /* child */
                        i = *(unsigned int *)&a[[1]];
                        printf("%d\n", i);
                        exit(0);
                    }
EOF
                ${CC-cc} -o conftest $CFLAGS $CPPFLAGS $LDFLAGS \
                    conftest.c $LIBS > /dev/null 2>&1
                # Oopz 4.3 BSD doesn't have this.  Sorry.
                if test ! -x conftest ; then
                        dnl failed to compile for some reason
                        ac_cv_lbl_unaligned_fail=yes
                else
                        ./conftest > conftest.out
                        if test ! -s conftest.out ; then
                                ac_cv_lbl_unaligned_fail=yes
                        else
                                ac_cv_lbl_unaligned_fail=no
                        fi
                fi
                rm -f conftest* core core.conftest
                ;;
        esac])
    AC_MSG_RESULT($ac_cv_lbl_unaligned_fail)
    if test $ac_cv_lbl_unaligned_fail = yes ; then
            AC_DEFINE(LBL_ALIGN, 1,
                [Define if unaligned memory accesses fail.])
    fi
])


dnl
dnl Checks endianess
dnl
dnl usage:
dnl
dnl     AC_LIBNET_ENDIAN_CHECK
dnl
dnl results:
dnl
dnl     LIBNET_BIG_ENDIAN = 1   or
dnl     LIBNET_LIL_ENDIAN = 1
dnl

AC_DEFUN([AC_LIBNET_ENDIAN_CHECK],
    [AC_MSG_CHECKING(machine endianess)

    cat > conftest.c << EOF
#       include <stdio.h>
#       include <stdlib.h>

        int main()
        {
            union
            {
                short s;
                char c[[sizeof(short)]];
            } un;

            un.s = 0x0102;
            if (sizeof (short) == 2)
            {
                if (un.c [[0]] == 1 && un.c [[1]] == 2)
                {
                    printf("B\n");
                }
                else
                {
                    if (un.c [[0]] == 2 && un.c [[1]] == 1)
                    {
                        printf("L\n");
                    }
                }
            }
            else
            {
                printf("?\n");
            }
            return (EXIT_SUCCESS);
        }
EOF
        ${CC-cc} -o conftest $CFLAGS $CPPFLAGS $LDFLAGS conftest.c $LIBS > /dev/null 2>&1
        # Oopz 4.3 BSD doesn't have this.  Sorry.
        if test ! -x conftest ; then
dnl failed to compile for some reason
            ac_cv_libnet_endianess=unknown
        else
            ./conftest > conftest.out
            result=`cat conftest.out`
            if test $result = "B"; then
                ac_cv_libnet_endianess=big
            elif test $result = "L"; then
                ac_cv_libnet_endianess=lil
            else
                ac_cv_libnet_endianess=unknown
            fi                                
        fi
        rm -f conftest* core core.conftest

        AC_MSG_RESULT($ac_cv_libnet_endianess)

        if test $ac_cv_libnet_endianess = big ; then
            AC_DEFINE(LIBNET_BIG_ENDIAN, 1,
                [We are running on a big-endian machine.])
            ENDIANESS="LIBNET_BIG_ENDIAN"
            LIBNET_CONFIG_DEFINES="$LIBNET_CONFIG_DEFINES -DLIBNET_BIG_ENDIAN"
        elif test $ac_cv_libnet_endianess = lil ; then
            AC_DEFINE(LIBNET_LIL_ENDIAN, 1, 
                [We are running on a little-endian machine.])
            ENDIANESS="LIBNET_LIL_ENDIAN"
            LIBNET_CONFIG_DEFINES="$LIBNET_CONFIG_DEFINES -DLIBNET_LIL_ENDIAN"
        fi
    ])

dnl
dnl Improved version of AC_CHECK_LIB
dnl
dnl Thanks to John Hawkinson (jhawk@mit.edu)
dnl
dnl usage:
dnl
dnl     AC_LBL_CHECK_LIB(LIBRARY, FUNCTION [, ACTION-IF-FOUND [,
dnl         ACTION-IF-NOT-FOUND [, OTHER-LIBRARIES]]])
dnl
dnl results:
dnl
dnl     LIBS
dnl
 
define([AC_LBL_CHECK_LIB],
[AC_MSG_CHECKING([for $2 in -l$1])
dnl Use a cache variable name containing both the library and function name,
dnl because the test really is for library $1 defining function $2, not
dnl just for library $1.  Separate tests with the same $1 and different $2's
dnl may have different results.
ac_lib_var=`echo $1['_']$2['_']$5 | sed 'y%./+- %__p__%'`
AC_CACHE_VAL(ac_cv_lbl_lib_$ac_lib_var,
[ac_save_LIBS="$LIBS"
LIBS="-l$1 $5 $LIBS"
AC_TRY_LINK(dnl
ifelse([$2], [main], , dnl Avoid conflicting decl of main.
[/* Override any gcc2 internal prototype to avoid an error.  */
]ifelse(AC_LANG, CPLUSPLUS, [#ifdef __cplusplus
extern "C"
#endif
])dnl
[/* We use char because int might match the return type of a gcc2
    builtin and then its argument prototype would still apply.  */
char $2();
]),
            [$2()],
            eval "ac_cv_lbl_lib_$ac_lib_var=yes",
            eval "ac_cv_lbl_lib_$ac_lib_var=no")
LIBS="$ac_save_LIBS"
])dnl
if eval "test \"`echo '$ac_cv_lbl_lib_'$ac_lib_var`\" = yes"; then
  AC_MSG_RESULT(yes)
  ifelse([$3], ,
[changequote(, )dnl
  ac_tr_lib=HAVE_LIB`echo $1 | sed -e 's/[^a-zA-Z0-9_]/_/g' \
    -e 'y/abcdefghijklmnopqrstuvwxyz/ABCDEFGHIJKLMNOPQRSTUVWXYZ/'`
changequote([, ])dnl
  AC_DEFINE_UNQUOTED($ac_tr_lib)
  LIBS="-l$1 $LIBS"
], [$3])
else
  AC_MSG_RESULT(no)
ifelse([$4], , , [$4
])dnl
fi
])

dnl
dnl AC_LBL_LIBRARY_NET
dnl
dnl This test is for network applications that need socket() and
dnl gethostbyname() -ish functions.  Under Solaris, those applications
dnl need to link with "-lsocket -lnsl".  Under IRIX, they need to link
dnl with "-lnsl" but should *not* link with "-lsocket" because
dnl libsocket.a breaks a number of things (for instance:
dnl gethostbyname() under IRIX 5.2, and snoop sockets under most
dnl versions of IRIX).
dnl
dnl Unfortunately, many application developers are not aware of this,
dnl and mistakenly write tests that cause -lsocket to be used under
dnl IRIX.  It is also easy to write tests that cause -lnsl to be used
dnl under operating systems where neither are necessary (or useful),
dnl such as SunOS 4.1.4, which uses -lnsl for TLI.
dnl
dnl This test exists so that every application developer does not test
dnl this in a different, and subtly broken fashion.
 
dnl It has been argued that this test should be broken up into two
dnl seperate tests, one for the resolver libraries, and one for the
dnl libraries necessary for using Sockets API. Unfortunately, the two
dnl are carefully intertwined and allowing the autoconf user to use
dnl them independantly potentially results in unfortunate ordering
dnl dependancies -- as such, such component macros would have to
dnl carefully use indirection and be aware if the other components were
dnl executed. Since other autoconf macros do not go to this trouble,
dnl and almost no applications use sockets without the resolver, this
dnl complexity has not been implemented.
dnl
dnl The check for libresolv is in case you are attempting to link
dnl statically and happen to have a libresolv.a lying around (and no
dnl libnsl.a).
dnl
AC_DEFUN([AC_LBL_LIBRARY_NET],
[
    # Most operating systems have gethostbyname() in the default searched
    # libraries (i.e. libc):
    AC_CHECK_FUNC(gethostbyname, ,
        # Some OSes (eg. Solaris) place it in libnsl:
        AC_LBL_CHECK_LIB(nsl, gethostbyname, ,
            # Some strange OSes (SINIX) have it in libsocket:
            AC_LBL_CHECK_LIB(socket, gethostbyname, ,
                # Unfortunately libsocket sometimes depends on libnsl.
                # AC_CHECK_LIB's API is essentially broken so the
                # following ugliness is necessary:
                AC_LBL_CHECK_LIB(socket, gethostbyname,
                    LIBS="-lsocket -lnsl $LIBS",
                    AC_CHECK_LIB(resolv, gethostbyname),
                    -lnsl))))
    AC_CHECK_FUNC(socket, , AC_CHECK_LIB(socket, socket, ,
        AC_LBL_CHECK_LIB(socket, socket, LIBS="-lsocket -lnsl $LIBS", ,
            -lnsl)))
    # DLPI needs putmsg under HPUX so test for -lstr while we're at it
    AC_CHECK_LIB(str, putmsg)
    ])

