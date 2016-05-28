#!/bin/bash -e

ROOT=$(git rev-parse --show-toplevel)

# build eglibc
# Please note that the only modification we made to
# libc is that we instrument the call to mmap syscall.
# We modify the mmap call in the dynamic linker to make 
# it always map the memory to a random address;
# other than that, we did not modify anything.
cd $ROOT/eglibc-2.19
./build-libc.sh

# build RuntimeASLR
cd $ROOT/pin-71313/source/tools/RuntimeASLR
./build-raslr.sh

# build Nginx
cd $ROOT/experiments/nginx-1.4.0
./build-nginx.sh

