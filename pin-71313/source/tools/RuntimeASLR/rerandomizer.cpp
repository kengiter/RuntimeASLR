
/*
 * rerandomizer: a shared library for 
 * remapping address space, cleaning up
 * address space, and transfering control
 */

#define UINT64 unsigned long
#define UINT32 unsigned int
#define VOID void
#define BOOl bool
#define REG UINT32

#include <iostream>
#include <string>
#include <sys/mman.h>
#include "remap_mgr.h"

using namespace std;


// remapping API
extern "C" void raslr_remap(void *v)
{
	RemapParams *params = (RemapParams *)v;
	RemapMgr remapMgr;
	remapMgr.RemapAllMaps(params);
}

