#!/bin/bash -e

CURDIR="$( cd "$( dirname "$0" )" && pwd )"
BINDIR=obj-intel64
OBJFILE=$BINDIR/pointer_tracker.o
BINFILE=$BINDIR/pointer_tracker.so
OBJFILE1=$BINDIR/policy_generator.o
BINFILE1=$BINDIR/policy_generator.so
OUTPUT=$CURDIR/outputs

if [ ! -d "$BINDIR" ]
then
  mkdir $BINDIR
fi

if [ -f "$BINFILE" ]
then
  rm $BINFILE $OBJFILE
fi

if [ -f "$BINFILE1" ]
then
  rm $BINFILE1 $OBJFILE1
fi

make $BINFILE
make $BINFILE1


g++ -fPIC -shared rerandomizer.cpp -o $BINDIR/rerandomizer.so


if [[ ! -e $OUTPUT ]]; then
	mkdir $OUTPUT
fi
