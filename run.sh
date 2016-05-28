#!/bin/bash -e

CURDIR="$( cd "$( dirname "$0" )" && pwd )"
RASLRDIR=$CURDIR/pin-71313/source/tools/RuntimeASLR
BINDIR=$RASLRDIR/obj-intel64
BINGEN=$BINDIR/policy_generator.so
BINTRACK=$BINDIR/pointer_tracker.so
BINNGINX=$CURDIR/experiments/nginx-1.4.0/prefix/sbin/nginx

# setup loader for random mmap()
LOADERLINK=/lib64/ld-rmmap-x86-64.so.2
if [ ! -f $LOADERLINK ]; then
  ROOT=$(git rev-parse --show-toplevel)
  LOADER=$ROOT/eglibc-2.19/libc/prefix/lib/ld-2.19.so
  if [ ! -f $LOADER ]; then
    $LOADER=$BINDIR/ld-rmmap-x86-64.so.2
  fi
  sudo ln -s $LOADER $LOADERLINK
fi


# must work under Pin's directory
cd $RASLRDIR

LDPATH=/usr/lib/x86_64-linux-gnu:/lib/x86_64-linux-gnu:/lib64
# generating taint policies
# configure how many runs you want to generate the tracking policy
# usually single run is enough
NRUNS=1
if [ -f "$BINGEN" ]
then
  NRUN=1
  while [ $NRUN -le $NRUNS ]
  do
    echo "Generating pointer tracking policy - $NRUN/$NRUNS"
    sudo LD_LIBRARY_PATH=$LDPATH $CURDIR/pin-71313/intel64/bin/pinbin_rmmap -t $BINGEN -nruns=$NRUNS -nrun=$NRUN -- $BINNGINX
    sudo $BINNGINX -s stop
    NRUN=`expr $NRUN + 1`
  done
fi

# do runtime aslr
if [ -f "$BINGEN" ]
then
  sudo LD_LIBRARY_PATH=$LDPATH $CURDIR/pin-71313/intel64/bin/pinbin_rmmap -t $BINTRACK -- $BINNGINX
fi
