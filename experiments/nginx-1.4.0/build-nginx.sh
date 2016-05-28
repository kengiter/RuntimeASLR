#!/bin/bash -e

NGINXDIR="$( cd "$( dirname "$0" )" && pwd )"
BINDIR=$NGINXDIR/prefix
OBJDIR=$NGINXDIR/objs

if [ ! -d "$BINDIR" ]
then
  mkdir $BINDIR
fi

echo Building in $BINDIR

if [ ! -d "$OBJDIR" ]
then
  ./configure --without-http_rewrite_module --prefix=$BINDIR --with-cc-opt="-pie -fPIC"
  sed -i -- 's/\$(LINK)/\$(LINK) \$(CFLAGS)/g' $OBJDIR/Makefile
fi

make
make install

