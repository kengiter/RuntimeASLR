#!/bin/bash -e

NJOB=`nproc`
ROOT=$(git rev-parse --show-toplevel)
MAKE="make --no-print-directory -j$NJOB"


SRC=$ROOT/eglibc-2.19/libc
cd $SRC
if [ ! -d "build" ]; then
  mkdir build
  mkdir prefix
fi

cd $SRC/build
../configure \
  CC=gcc \
  CFLAGS='-O3'\
  --prefix=$SRC/prefix \
  --disable-multi-arch \
  --disable-profile

$MAKE
$MAKE install

