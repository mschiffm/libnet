#!/bin/sh -ex
#
# A bootstrapping script that can be used to generate the autoconf,
# automake and libtool-related scripts of the build process.
#
# $Id: autogen.sh,v 1.2 2004/08/10 13:57:46 gkeramidas Exp $

trap "/bin/rm -fr autom4te.cache ; \
      echo 'Failed to regenerate autoconf/automake stuff.'" 0 1 2 15
set -e

rm -fr autom4te.cache
glibtoolize --copy --force
aclocal -I .
autoheader
automake -a -c --foreign
autoconf
rm -fr autom4te.cache

set +e
trap "echo $0 ok" 0 1 2 15
