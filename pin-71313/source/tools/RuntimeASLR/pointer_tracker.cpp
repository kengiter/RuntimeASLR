/*
 * pointer tracker: taint-tracking all pointers
 *
 * x86_64 only
 */

#include "raslr.h"

#include "pin.H"
#include <asm/unistd.h>
#include <fstream>
#include <iostream>
#include <stdlib.h>
#include <set>
#include <list>
#include <string.h>
#include <syscall.h>
#include <cstdarg>
#include <cassert>
#include <unistd.h>
#include <dlfcn.h>
#include <time.h>
#include <fcntl.h>
#include <link.h>

#include "proc_mgr.h"
#include "taint_mgr.h"
#include "syscall_mgr.h"
#include "policy_rep.h"

using namespace std;

#define NUM_PTR_REGS 53

#if defined(TARGET_MAC)
#define MALLOC "_malloc"
#define FREE "_free"
#else
#define MALLOC "malloc"
#define FREE "free"
#endif


/* global variables */
// layer of the current process
UINT32 forkLayer = 0;
// key for accessing TLS storage in the threads. initialized once
static  TLS_KEY tls_key_syscall_ctx;
static  TLS_KEY tls_key_sp;

// manager instances
ProcMgr *procMgr;
TaintMgr *taintMgr;
SyscallMgr *syscallMgr;

// policies for pointer tracking
list<TaintPolicy *>taintPolicies;
// opcodes covered by our policy
set<UINT32>taintOpcs;

// base address of stack
UINT64 curStackBase = 0;
// fp of the interface of rerandomizer
VOID *(*raslr_mremap)(VOID *, size_t, size_t, int, VOID*);
// some temp variables
mapping *toUnmapMaps = NULL;
mapping *curToUnmap = NULL;

// remapping info
struct RemappingParams {
	UINT64 regs[NUM_PTR_REGS];
	mapping *maps;
	mapping *pinMaps;
	remapping *remaps;
	void *(*raslr_mremap)(void *, size_t, size_t, int, void*);
	UINT64 mangleKeyAddr;
	set<TaintedPtr>taintedPtrs;
};
RemappingParams *params = new RemappingParams();


// extract input taintness state of ins
VOID GetInsInputState(CONTEXT *ctx, InsRep *rep, 
		UINT64 addrR = 0, UINT32 readSize = 0,
		UINT64 addrW = 0, UINT32 writeSize = 0 ) { 
#ifdef VERBOSE_MODE
	if (readSize > 0)
		cout<<"addrR="<<hex<<addrR<<endl;
	if (writeSize > 0)
		cout<<"addrW="<<hex<<addrW<<endl;
#endif
	// initialization
	rep->taintsInR = 0;

	UINT8 *tir = (UINT8 *)&(rep->taintsInR);
	// check if the operand is an addresses
	for (UINT8 i = 0; i < rep->opeCount; ++i) {
		// only check read opes
		if(!(((rep->opeRead)>>i)&1))
			continue;
		UINT8 opeT = ((rep->opeTypes)>>(i*4))&0xf;
		if (opeT == OpeTypeReg) {
			tir[i] = taintMgr->GetRegTaint((REG)(rep->opeData[i]));
		}
		else if (opeT == OpeTypeMem) {
			if (readSize == 8) 
				tir[i] = taintMgr->GetMemTaint(addrR);
			else if (readSize == 16) {
				tir[i] = taintMgr->GetMemTaint(addrR);
				tir[i] |= (taintMgr->GetMemTaint(addrR + 8))<<4;
			}
		}
		else if (opeT == OpeTypeImm) {
			if (procMgr->IsValidAddress(rep->opeData[i]))
				tir[i] = 1;
		}
		//else
		//  raslr_not_reachable();
	}
	if (writeSize > 0)
		rep->toWriteAddr = addrW;

#ifdef USE_SUB_POLICY
	rep->etp = FindPolicy(taintPolicies, rep);
	// if it has sub policies, load the highest bits
	if (rep->etp && rep->etp->flags) {
		// load hibits
		for (UINT8 i = 0; i < rep->opeCount; ++i) {
			// only check read opes
			if(!(((rep->opeRead)>>i)&1))
				continue;
			UINT8 opeT = ((rep->opeTypes)>>(i*4))&0xf;
			if (opeT == OpeTypeReg) {
				UINT8 opeWidth = ((UINT8 *)&(rep->opeWidths))[i];
				// only consider general purpose regs
				REG fullReg = utils::GetFullReg((REG)(rep->opeData[i]));
				// FIXME: how about non-general regs?
				if (REG_is_gr64(fullReg)) {
#ifdef SUB_POLICY_HIBIT
					UINT64 regV = PIN_GetContextReg(ctx, fullReg);
					rep->hiBits[i] = utils::HiBit(regV);
#endif
				}
				else if (opeWidth == 128) {
					UINT64* regP = new UINT64[2];
					PIN_GetContextRegval(ctx, fullReg, (UINT8 *)regP);
					// check first 64-bit
#ifdef SUB_POLICY_HIBIT
					rep->hiBits[i] = utils::HiBit(regP[0]);
#endif
				}
			}
			else if (opeT == OpeTypeMem) {
#ifdef SUB_POLICY_HIBIT
				if (readSize == 8 || readSize == 16)
					rep->hiBits[i] = utils::HiBit(*(UINT64 *)addrR);
#endif
			}
			else if (opeT == OpeTypeImm) {
#ifdef SUB_POLICY_HIBIT
				rep->hiBits[i] = utils::HiBit(rep->opeData[i]);
#endif
			}
		}
	}
#endif
}

VOID PropagateCallIns (UINT64 addrW) {
	taintMgr->TaintMem(addrW);
#ifdef VERBOSE_MODE
	cout<<"# Taint return address at "<<hex<<addrW<<endl;
#endif
}

// FIXME: be careful for special return address usages
// after ret
VOID PropagateRetIns (UINT64 addrR) {
	UINT64 *sp = static_cast<UINT64*>(
			PIN_GetThreadData(tls_key_sp, PIN_ThreadId()));
	if (!sp) {
		sp = new UINT64(0);
		PIN_SetThreadData(tls_key_sp, sp, PIN_ThreadId());
		memset((void *)(curStackBase), 0, addrR - curStackBase);
	}
	else {
		if (*sp && addrR > *sp) {
			memset((void *)*sp, 0, addrR - *sp);
		}
		// no stack pivot, but may have save registers
		// conservatively zero them
		else {
			memset((void *)(addrR - 14*8), 0, 14*8);
		}
		*sp = 0;
	}
	taintMgr->UntaintMemRange(curStackBase, addrR);
#ifdef VERBOSE_MODE
	cout<<"# Untaintmem range <"<<hex<<curStackBase<<
		", "<<addrR<<">"<<endl;
#endif
}

VOID HandleStackPivotIns(CONTEXT *ctx) {
	UINT64 *sp = static_cast<UINT64*>(
			PIN_GetThreadData(tls_key_sp, PIN_ThreadId()));
	if (!sp) {
		sp = new UINT64(PIN_GetContextReg(ctx, REG_RSP));
		PIN_SetThreadData(tls_key_sp, sp, PIN_ThreadId());
	}
	else {
		*sp = PIN_GetContextReg(ctx, REG_RSP);
	}
}

// handle general instructions
VOID PropagateIns (InsRep *rep, CONTEXT *ctx) {
#ifndef USE_SUB_POLICY
	rep->etp = FindPolicy(taintPolicies, rep);
#endif
	if (!rep->etp)
		return;
	TaintPolicy *etp = rep->etp;

#ifdef USE_SUB_POLICY
	SubTaintPolicy *estp = NULL;
	if (etp->flags > 0) {
#ifdef SUB_POLICY_HIBIT
		estp = FindSubPolicy(etp->subPolicies, rep->hiBits,
				rep->opeCount);
#endif
		raslr_assert(estp, "Cannot find sub policy\n");
	}
#endif

	cout<<hex;
	for (UINT8 i = 0; i < rep->opeCount; ++i) {
		if (!(((rep->opeWritten)>>i)&1))
			continue;

		UINT8 opeWidth = ((UINT8 *)&(rep->opeWidths))[i];
#ifdef USE_SUB_POLICY
		UINT8 *to = (UINT8 *)&(estp->taintsOut);
		UINT8 *flags = (UINT8 *)&(estp->flags);
#else
		UINT8 *to = (UINT8 *)&(etp->taintsOut);
		UINT8 *flags = (UINT8 *)&(etp->flags);
#endif
		UINT8 opeT = ((rep->opeTypes)>>(i*4))&0xf;
		if (opeT == OpeTypeReg) {
			REG reg = (REG)(rep->opeData[i]);
			REG fullReg = utils::GetFullReg(reg);
			if (REG_is_gr64(fullReg)) {
				UINT64 regV = PIN_GetContextReg(ctx, fullReg);
#ifdef VERBOSE_MODE
				BOOL isTainted = false;
				BOOL isUntainted = false;
#endif
				if (flags[i]) {
					// do tainting
					if (procMgr->IsValidAddress(regV)) {
						taintMgr->TaintReg(reg);
#ifdef VERBOSE_MODE
						isTainted = true;
#endif
					}
#ifdef PTR_MANGLE
					else if (procMgr->IsMangledAddress(regV, ctx)) {
						taintMgr->TaintReg(reg, 2);
#ifdef VERBOSE_MODE
						isTainted = true;
#endif
					}
#endif
					// do untainting
					else {
						taintMgr->UntaintReg(reg);
#ifdef VERBOSE_MODE
						isUntainted = true;
#endif
					}
				}
				// do tainting
				else if (to[i]){
					taintMgr->TaintReg(reg, to[i]);
#ifdef VERBOSE_MODE
					isTainted = true;
#endif
				}
				// do untainting
				else {
					taintMgr->UntaintReg(reg);
#ifdef VERBOSE_MODE
					isUntainted = true;
#endif
				}
#ifdef VERBOSE_MODE
				// for testing
				if (isTainted) {
					// print some debugging info here
				}
				else if (isUntainted) {
					// print some debugging info here
				}
#endif
			}
			else if (opeWidth == 128) {
				UINT64* regP = new UINT64[2];
				PIN_GetContextRegval(ctx, reg, (UINT8 *)regP);
				UINT8 taint = 0;
				// check first 64-bit
				if (flags[i]&0xf) {
					if (procMgr->IsValidAddress(regP[0]))
						taint = 1;
				}
				else if (to[i]&0xf) {
					taint = 1;
				}

				// check second 64-bit
				if (flags[i]&(0xf<<4)) {
					if (procMgr->IsValidAddress(regP[1]))
						taint |= 1<<4;
				}
				else if (to[i]&(0xf<<4)) {
					taint |= 1<<4;
				}
				taintMgr->TaintReg(reg, taint);

#ifdef VERBOSE_MODE
				if (taint&0xf) {
					// print some debugging info here
				}
				else if (!(taint&0xf)){
					// print some debugging info here
				}
				else if (taint&(0xf<<4)) {
					// print some debugging info here
				}
				else if (!(taint&(0xf<<4))){
					// print some debugging info here
				}
#endif
			}
		}
		else if (opeT == OpeTypeMem) {
			if (opeWidth != 128) {
#ifdef VERBOSE_MODE
				// for testing
				BOOL isTainted = false;
				BOOL isUntainted = false;
#endif
				if (flags[i]) {
					// do tainting
					if (procMgr->IsValidAddress(*(UINT64 *)rep->toWriteAddr)) {
						taintMgr->TaintMem(rep->toWriteAddr);
#ifdef VERBOSE_MODE
						isTainted = true;
#endif
					}
#ifdef PTR_MANGLE
					else if (procMgr->IsMangledAddress(
								*(UINT64 *)rep->toWriteAddr, ctx)) {
						taintMgr->TaintMem(rep->toWriteAddr, 2);
#ifdef VERBOSE_MODE
						isTainted = true;
#endif
					}
#endif
					// do untainting
					else {
						taintMgr->UntaintMem(rep->toWriteAddr);
#ifdef VERBOSE_MODE
						isUntainted = true;
#endif
					}
				}
				// do tainting
				else if (to[i]) { 
					taintMgr->TaintMem(rep->toWriteAddr, to[i]);
#ifdef VERBOSE_MODE
					isTainted = true;
#endif
				}
				// do untainting
				else {
					taintMgr->UntaintMem(rep->toWriteAddr);
#ifdef VERBOSE_MODE
					isUntainted = true;
#endif
				}
#ifdef VERBOSE_MODE
				// for testing
				if (isTainted) {
					// print some debugging info here
				}
				else if (isUntainted) {
					// print some debugging info here
				}
#endif
			}
			else if (opeWidth == 128) {
#ifdef VERBOSE_MODE
				BOOL isTainted = false;
#endif
				// check first 64-bit
				UINT64 addrW = rep->toWriteAddr;
				if (flags[i]&0xf) {
					if (procMgr->IsValidAddress(*(UINT64 *)addrW)) {
						taintMgr->TaintMem(addrW);
#ifdef VERBOSE_MODE
						isTainted = true;
#endif
					}
					else
						taintMgr->UntaintMem(addrW);
				}
				else if (to[i]&0xf) {
					taintMgr->TaintMem(addrW);
#ifdef VERBOSE_MODE
					isTainted = true;
#endif
				}
				else
					taintMgr->UntaintMem(addrW);
#ifdef VERBOSE_MODE
				// for testing
				UINT64 mem = *(UINT64 *)addrW;
				if (isTainted) {
					// print some debugging info here
				}
				else {
					// print some debugging info here
				}

				isTainted = false;
#endif

				// check second 64-bit
				if (flags[i]&(0xf<<4)) {
					if (procMgr->IsValidAddress(*(UINT64 *)(addrW + 8))) {
						taintMgr->TaintMem(addrW + 8);
#ifdef VERBOSE_MODE
						isTainted = true;
#endif
					}
					else
						taintMgr->UntaintMem(addrW + 8);
				}
				else if (to[i]&(0xf<<4)) {
					taintMgr->TaintMem(addrW + 8);
#ifdef VERBOSE_MODE
					isTainted = true;
#endif
				}
				else
					taintMgr->UntaintMem(addrW + 8);
#ifdef VERBOSE_MODE
				// for testing
				mem = *(UINT64 *)(addrW + 8);
				if (isTainted) {
					// print some debugging info here
				}
				else {
					// print some debugging info here
				}
#endif
			}
		}
	}
}

/* do runtime re-randomization here */
struct RemapParams {
	UINT64 Regs[20];
	remapping *remaps;
	ProcMgr *procMgr;
	TaintMgr *taintMgr;
};

VOID PostDetach(VOID *v) {
#ifdef MICRO_BENCH
	cout<<"[cycle] After detaching: "<<dec<<utils::rdtsc()<<endl;
#endif
	VOID* hRemap = dlopen("./obj-intel64/rerandomizer.so", 
			RTLD_NOW);
	VOID (*fRemap)(VOID *) = 
		(VOID (*)(VOID*))dlsym(hRemap, "raslr_remap");

	fRemap(v);
}

mapping *RemapMap(mapping *map, CONTEXT *ctx, 
		UINT64 newBase = 0, UINT32 vSize = 0,
		BOOL unmap = true) {
	UINT64 oldStart = map->start, oldEnd = map->end;
	UINT64 size = oldEnd - oldStart;
	UINT32 prot = map->protI;
	UINT64 newStart = (UINT64)mmap(
			(caddr_t)newBase, 
			vSize > 0 ? vSize : size, 
			map->protI|PROT_WRITE,
			MAP_ANONYMOUS | MAP_PRIVATE,
			-1, 0);
	if (unmap) {
		munmap((VOID *)newStart, vSize > 0 ? vSize : size);
		newStart = (UINT64)raslr_mremap((VOID *)map->start, 
				map->end - map->start,
				map->end - map->start,
				MREMAP_MAYMOVE|MREMAP_FIXED, (VOID *)newStart);
	}
	else {
		// copying data
		if (!(prot&PROT_READ)) {
			mprotect((void *)oldStart, size, prot|PROT_READ);
		}
		memcpy((void *)newStart, (void *)(oldStart), size);
		if (!(prot&PROT_READ))
			mprotect((void *)oldStart, size, prot);
	}
	// updating maps
	mapping *newMap = procMgr->AddMap(newStart, 
			newStart + size, prot|(unmap?0:PROT_WRITE));
	mapping *deMap = procMgr->DeleteMap(oldStart, oldEnd);
	procMgr->AddRemap(deMap, newMap);
	if (!unmap) {
		if (!toUnmapMaps)
			toUnmapMaps = deMap;
		else
			curToUnmap->next = deMap;
		curToUnmap = deMap;
	}
	// updating taintness
	taintMgr->UpdateMemRange(oldStart, oldEnd, 
			newStart - oldStart);
	UINT64 keyAddr = 
		PIN_GetContextReg(ctx, REG_SEG_FS_BASE) + 0x30;
	if (keyAddr >= oldStart && keyAddr < oldEnd)
		keyAddr += (newStart - oldStart);
	UINT64 mangleKey = *(UINT64 *)keyAddr;
	taintMgr->UpdatePtrsRange(oldStart, oldEnd, 
			newStart - oldStart, mangleKey);
	taintMgr->UpdateRegsRange(ctx, 
			oldStart, oldEnd, newStart - oldStart);

	if (!(prot&PROT_WRITE) && !unmap) {
		mprotect((void *)newMap->start, size, prot);
		newMap->protI ^= PROT_WRITE;
	}
	// FIXME: pin may access the program data
	return newMap;
}

/* interface for re-randomization */
VOID RuntimeASLR(CONTEXT *ctx) {
#ifdef MICRO_BENCH
	cout<<"[cycle] Enter raslr: "<<dec<<utils::rdtsc()<<endl;
#endif

	// print time for evaluation
#ifdef MEASURE_TIME
	time_t timer;
	char buffer[26];
	struct tm* tm_info;
	time(&timer);
	tm_info = localtime(&timer);
	strftime(buffer, 26, "%Y:%m:%d %H:%M:%S", tm_info);
	cout<<"[raslr] tracking end time: "<<buffer<<endl;
#endif

	//procMgr->PrintAppMaps();
	//procMgr->PrintPinMaps();

#ifdef VERBOSE_MODE
	taintMgr->PrintTaintedPtrs(ctx); 
	taintMgr->PrintTaintedRegs(ctx);
#endif
	taintMgr->PostPtrPruning(ctx); 
	// two rounds remapping: 1st for modules, 2nd
	// round for individual sections, e.g., stack, heap
	set<mapping *>handledMaps;
	remapping *remaps = NULL; 
	remapping *curRemap = NULL; 
	for (IMG img= APP_ImgHead(); IMG_Valid(img); img = IMG_Next(img)) {
		UINT64 base = IMG_LowAddress(img);
		UINT64 end = IMG_HighAddress(img);
		mapping *baseMap = procMgr->FindMap(base);
		mapping *endMap = procMgr->FindMap(end);
		// remap the first map of this module
		UINT64 startMapStart = baseMap->start;
		UINT64 endMapEnd = endMap->end;

		remapping *baseRemap = new remapping();
		baseRemap->oldMap = baseMap;
		baseRemap->reserveSize = endMap->end - baseMap->start;
		if (!remaps)
			remaps = baseRemap;
		else 
			curRemap->next = baseRemap;
		curRemap = baseRemap;
		handledMaps.insert(baseMap);

		mapping *it = procMgr->maps;
		while(it) {
			if (it->start > startMapStart && 
					it->end <= endMapEnd) {
				// remapping the following maps with fixed
				// offsets
				remapping *remap = new remapping();
				remap->oldMap = it;
				remap->baseRemap = baseRemap;
				remap->fixOffset = it->start - startMapStart;
				curRemap->next = remap;
				curRemap = remap;
				handledMaps.insert(it);
			}
			it = it->next;
		}
	}

	// remapping other maps
	mapping *it = procMgr->maps;
	while(it) {
		if (handledMaps.find(it) != handledMaps.end()) {
			it = it->next;
			continue;
		}
		remapping *remap = new remapping();
		remap->oldMap = it;
		curRemap->next = remap;
		curRemap = remap;
		handledMaps.insert(it);
		it = it->next;
	}

	params->maps = procMgr->maps;
	params->pinMaps = procMgr->pinMaps;
	params->remaps = remaps;
	params->raslr_mremap = raslr_mremap;
	params->mangleKeyAddr = 
		PIN_GetContextReg(ctx, REG_SEG_FS_BASE) + 0x30;
	params->taintedPtrs = taintMgr->taintedPtrs;
	// save registers
	params->regs[0] = PIN_GetContextReg(ctx, REG_RAX);
	params->regs[1] = PIN_GetContextReg(ctx, REG_RBX);
	params->regs[2] = PIN_GetContextReg(ctx, REG_RCX);
	params->regs[3] = PIN_GetContextReg(ctx, REG_RDX);
	params->regs[4] = PIN_GetContextReg(ctx, REG_RSI);
	params->regs[5] = PIN_GetContextReg(ctx, REG_RDI);
	params->regs[6] = PIN_GetContextReg(ctx, REG_RBP);
	params->regs[7] = PIN_GetContextReg(ctx, REG_RSP);
	params->regs[8] = PIN_GetContextReg(ctx, REG_R8);
	params->regs[9] = PIN_GetContextReg(ctx, REG_R9);
	params->regs[10] = PIN_GetContextReg(ctx, REG_R10);
	params->regs[11] = PIN_GetContextReg(ctx, REG_R11);
	params->regs[12] = PIN_GetContextReg(ctx, REG_R12);
	params->regs[13] = PIN_GetContextReg(ctx, REG_R13);
	params->regs[14] = PIN_GetContextReg(ctx, REG_R14);
	params->regs[15] = PIN_GetContextReg(ctx, REG_R15);

	// save fp registers
	PIN_GetContextRegval(ctx, REG_XMM0, (UINT8 *)&(params->regs[16]));
	PIN_GetContextRegval(ctx, REG_XMM1, (UINT8 *)&(params->regs[18]));
	PIN_GetContextRegval(ctx, REG_XMM2, (UINT8 *)&(params->regs[20]));
	PIN_GetContextRegval(ctx, REG_XMM3, (UINT8 *)&(params->regs[22]));
	PIN_GetContextRegval(ctx, REG_XMM4, (UINT8 *)&(params->regs[24]));
	PIN_GetContextRegval(ctx, REG_XMM5, (UINT8 *)&(params->regs[26]));
	PIN_GetContextRegval(ctx, REG_XMM6, (UINT8 *)&(params->regs[28]));
	PIN_GetContextRegval(ctx, REG_XMM7, (UINT8 *)&(params->regs[30]));
	PIN_GetContextRegval(ctx, REG_XMM8, (UINT8 *)&(params->regs[32]));
	PIN_GetContextRegval(ctx, REG_XMM9, (UINT8 *)&(params->regs[34]));
	PIN_GetContextRegval(ctx, REG_XMM10, (UINT8 *)&(params->regs[36]));
	PIN_GetContextRegval(ctx, REG_XMM11, (UINT8 *)&(params->regs[38]));
	PIN_GetContextRegval(ctx, REG_XMM12, (UINT8 *)&(params->regs[40]));
	PIN_GetContextRegval(ctx, REG_XMM13, (UINT8 *)&(params->regs[42]));
	PIN_GetContextRegval(ctx, REG_XMM14, (UINT8 *)&(params->regs[44]));
	PIN_GetContextRegval(ctx, REG_XMM15, (UINT8 *)&(params->regs[46]));

	// save seg registers
	params->regs[48] = PIN_GetContextReg(ctx, REG_SEG_FS_BASE);
	params->regs[49] = PIN_GetContextReg(ctx, REG_SEG_GS_BASE);

	// save flag registers
	params->regs[50] = PIN_GetContextReg(ctx, REG_RFLAGS);
	params->regs[51] = PIN_GetContextReg(ctx, REG_MXCSR);

	// save rip
	params->regs[52] = PIN_GetContextReg(ctx, REG_RIP);

	//PostDetach((VOID *)params);
	PIN_Detach();
}

// do re-randomization when clone syscall returns
VOID CloneExit(CONTEXT *ctx) {

	UINT64 pid = PIN_GetContextReg(ctx, REG_RAX);
	if (pid == 0) {
		++forkLayer;
		if (forkLayer == RAND_FORK_LAYER) {
			RuntimeASLR(ctx);
		}
		else {
		}
	}
}


// do some initializations at the first instructioin
static BOOL isFirstIns = true;
VOID InitAtFirstIns(CONTEXT *ctx) {
#ifdef MEASURE_TIME
	// print time for evaluation
	time_t timer;
	char buffer[26];
	struct tm* tm_info;
	time(&timer);
	tm_info = localtime(&timer);
	strftime(buffer, 26, "%Y:%m:%d %H:%M:%S", tm_info);
	cout<<"[raslr] start time: "<<buffer<<endl;
#endif

	// image info can only be read when
	// the program is started
	procMgr->LoadInitMaps(ctx);

	// get stack base
	UINT64 rspV = PIN_GetContextReg(ctx, REG_RSP);
	mapping *it = procMgr->maps;
	while(it) {
		if (it->start < rspV && rspV < it->end) {
			curStackBase = it->start;
			it->mapType = StackMap;
			break;
		}
		it = it->next;
	}
	// taint initial pointers
	taintMgr->TaintInitPtrs(ctx);
}


// testing
VOID PrintMem(CONTEXT *ctx, UINT64 addr, 
		ProcMgr *procMgr) {
	if (procMgr->maps) {
		mapping *map = procMgr->FindMap(addr);
		if (map && map->protI&PROT_READ) {
			if (taintMgr->GetMemTaint(addr))
				cout<<"[Tainted] ";
			else
				cout<<"[Untainted] ";
			cout<<"*"<<hex<<addr<<"="<<
				*(UINT64*)addr<<endl;
		}
	}
}

/* instrumentation */
// do tainting and taint propagation
static BOOL isFollowClone = false;
VOID Instruction(INS ins, VOID *v)
{

#ifdef VERBOSE_MODE
	INS_InsertCall(
			ins, IPOINT_BEFORE, (AFUNPTR)PrintMem,
			IARG_CONST_CONTEXT, 
			IARG_ADDRINT, 0x7ffff7fb7a40,
			IARG_PTR, procMgr,
			IARG_END);
#endif

#ifdef VERBOSE_MODE
	INS_InsertCall(
			ins, IPOINT_BEFORE, (AFUNPTR)utils::PrintIns,
			IARG_PTR, new string(INS_Disassemble(ins)),
			IARG_ADDRINT, INS_Address(ins),
			IARG_END);
#endif

	// do initialization and taint initial pointers prepared by OS
	// at first instruction
	if (isFirstIns) {
		INS_InsertCall(
				ins, IPOINT_BEFORE, (AFUNPTR)InitAtFirstIns,
				IARG_CONST_CONTEXT, 
				IARG_END);
		isFirstIns = false;
	}

	// instrument sys_clone
	else if (INS_IsSyscall(ins)) {
		INS insP0 = INS_Prev(ins);
		INS insP1 = INS_Prev(insP0);
		if (insP1 != INS_Invalid()) 
			if (INS_OperandIsImmediate(insP0, 1) && 
					INS_OperandImmediate(insP0, 1) == __NR_clone) 
				// sys_clone for creating process, e.g., fork
				// both multithread and fork use clone syscall, so use the flags 
				// CLONE_CHILD_SETTID|CLONE_CHILD_CLEARTID|SIGCHLD(0x1200011) 
				// passed to clone to differenciate them.
				if (INS_OperandIsImmediate(insP1, 1) && 
						INS_OperandImmediate(insP1, 1) == 0x1200011) 
					isFollowClone = true;
	}
	else if (isFollowClone) {
		INS_InsertCall(
				ins, IPOINT_BEFORE, (AFUNPTR)CloneExit,
				IARG_CONTEXT, 
				IARG_END);
		isFollowClone = false;
	}

	// handling for special ins
	OPCODE opc = INS_Opcode (ins);

	if (INS_IsCall(ins)) {
		// call into memory
		if (INS_IsMemoryRead(ins))
			INS_InsertCall(
					ins, IPOINT_BEFORE, (AFUNPTR)PropagateCallIns,
					IARG_MEMORYOP_EA, 1,
					IARG_END);
		else
			INS_InsertCall(
					ins, IPOINT_BEFORE, (AFUNPTR)PropagateCallIns,
					IARG_MEMORYOP_EA, 0,
					IARG_END);

		return;
	}
	else if (INS_IsRet(ins)) {
		INS_InsertCall(
				ins, IPOINT_BEFORE, (AFUNPTR)PropagateRetIns,
				IARG_MEMORYOP_EA, 0,
				IARG_END);
		return;
	}
	// stack pivot
	else if (INS_IsSub(ins) && 
			INS_OperandIsImmediate(ins, 1) &&
			INS_OperandReg(ins, 0) == REG_RSP) {
		INS_InsertCall(
				ins, IPOINT_AFTER, (AFUNPTR)HandleStackPivotIns,
				IARG_CONST_CONTEXT, 
				IARG_END);
		return;
	}

	// filtering
	if (
			INS_HasMemoryRead2(ins) || 
			opc ==  XED_ICLASS_STOSB ||
			//INS_IsCall(ins) ||
			//INS_IsRet(ins) ||
			INS_IsBranch(ins)
		 )
		return;
	// the instrumented ins must modify something
	if (!utils::HasPtrWritten(ins))
		return;
	// the instrumented ins must read something
	if (INS_MaxNumRRegs(ins) < 1 && !utils::HasImmediate(ins) &&
			!INS_IsMemoryRead(ins) && opc != XED_ICLASS_RDTSC)
		return;
	// must be covered in the taint policies
	if (taintOpcs.find(opc) == taintOpcs.end())
		return;

	InsRep *rep = new InsRep(ins);
	if (!FindPolicy(taintPolicies, rep, false))
		return;

	// do instrumentations
	// get input taintness of this ins
	if (!INS_IsMemoryRead(ins) && !INS_IsMemoryWrite(ins)) {
		INS_InsertCall(
				ins, IPOINT_BEFORE, (AFUNPTR)GetInsInputState,
				IARG_CONST_CONTEXT, 
				IARG_PTR, rep,
				IARG_ADDRINT, 0, // placeholder
				IARG_UINT32, 0, // placeholder
				IARG_ADDRINT, 0, // placeholder
				IARG_UINT32, 0, // placeholder
				IARG_END);
	}
	else if (INS_IsMemoryRead(ins) && !INS_IsMemoryWrite(ins)) {
		INS_InsertCall(
				ins, IPOINT_BEFORE, (AFUNPTR)GetInsInputState,
				IARG_CONST_CONTEXT, 
				IARG_PTR, rep,
				IARG_MEMORYOP_EA, 0,
				IARG_UINT32, INS_MemoryReadSize(ins),
				IARG_ADDRINT, 0, // placeholder
				IARG_UINT32, 0, // placeholder
				IARG_END);
	}
	else if (!INS_IsMemoryRead(ins) && INS_IsMemoryWrite(ins)) {
		INS_InsertCall(
				ins, IPOINT_BEFORE, (AFUNPTR)GetInsInputState,
				IARG_CONST_CONTEXT, 
				IARG_PTR, rep,
				IARG_ADDRINT, 0, // placeholder
				IARG_UINT32, 0, // placeholder
				IARG_MEMORYOP_EA, 0,
				IARG_UINT32, INS_MemoryWriteSize(ins),
				IARG_END);
	}
	else {
		INS_InsertCall(
				ins, IPOINT_BEFORE, (AFUNPTR)GetInsInputState,
				IARG_CONST_CONTEXT, 
				IARG_PTR, rep,
				IARG_MEMORYOP_EA, INS_MemoryOperandIsRead(ins, 1),
				IARG_UINT32, INS_MemoryReadSize(ins),
				IARG_MEMORYOP_EA, INS_MemoryOperandIsWritten(ins, 1),
				IARG_UINT32, INS_MemoryWriteSize(ins),
				IARG_END);
	}

	// do taint propagation
	INS_InsertCall(
			ins, IPOINT_AFTER, (AFUNPTR)PropagateIns,
			IARG_PTR, rep,
			// for testing
			IARG_CONST_CONTEXT, 
			IARG_END);
}

/* function hooking */
ADDRINT mallocSize = 0; 
VOID MallocBefore(ADDRINT size)
{
	mallocSize = size;
}

VOID MallocAfter(ADDRINT addr)
{
	HeapObj ho;
	ho.addr = addr;
	ho.size = mallocSize;
	procMgr->heapObjs.insert(ho);
	taintMgr->UntaintMemRange(addr, addr + mallocSize);
}

VOID FreeBefore(ADDRINT addr, CONTEXT *ctx)
{
	HeapObj ho;
	ho.addr = addr;
	set<HeapObj>::iterator it = procMgr->heapObjs.find(ho);
	if (it != procMgr->heapObjs.end()) {
		taintMgr->UntaintMemRange(addr, addr + it->size);
		//taintMgr->UntaintPtrsRange(addr, addr + it->size);
		//taintMgr->UntaintRegsRange(ctx, addr, addr + it->size);
		memset((void *)addr, 0, it->size);
		procMgr->heapObjs.erase(ho);
	}
	else {
	}
}

static VOID ImageLoad(IMG img, VOID * v)
{
	// do nothing 
	return;
}

/* Setting pointer sources */
VOID SyscallEntry(THREADID thread_id, 
		CONTEXT *ctx, SYSCALL_STANDARD std, void *v)
{
	SyscallCtx *sctx = static_cast<SyscallCtx*>
		(PIN_GetThreadData(tls_key_syscall_ctx, thread_id));
	if (!sctx)
		sctx = new SyscallCtx();

	sctx->num = PIN_GetSyscallNumber(ctx, std);
	sctx->arg0 = PIN_GetSyscallArgument(ctx, std, 0);
	sctx->arg1 = PIN_GetSyscallArgument(ctx, std, 1);
	sctx->arg2 = PIN_GetSyscallArgument(ctx, std, 2);
	sctx->arg3 = PIN_GetSyscallArgument(ctx, std, 3);
	sctx->arg4 = PIN_GetSyscallArgument(ctx, std, 4);
	sctx->arg5 = PIN_GetSyscallArgument(ctx, std, 5);

	PIN_SetThreadData(tls_key_syscall_ctx, sctx, thread_id);

}

VOID SyscallExit(THREADID thread_id, 
		CONTEXT *ctx, SYSCALL_STANDARD std, void *v)
{
	SyscallCtx *sctx = static_cast<SyscallCtx*>
		(PIN_GetThreadData(tls_key_syscall_ctx, thread_id));
	sctx->ret = PIN_GetSyscallReturn(ctx, std);
	sctx->ctx = ctx;
	syscallMgr->HandleSyscall(sctx);
}


////////////////////////////////////
/* main */
INT32 Usage()
{
	cerr << "Taint-tracking all pointers" << endl;
	return -1;
}

VOID InitAll() {
	PIN_SetSyntaxIntel();
	// Obtain  a key for TLS storage.
	tls_key_syscall_ctx = PIN_CreateThreadDataKey(0);
	tls_key_sp = PIN_CreateThreadDataKey(0);

	procMgr = new ProcMgr(getpid());
	taintMgr = new TaintMgr(procMgr);
	syscallMgr = new SyscallMgr(procMgr, taintMgr);

	// load taint policies
	FILE *policyFile = fopen(policyFilePath, "rb");
	raslr_assert(policyFile, "Cannot open policy file!");
	fseek(policyFile, 0L, SEEK_END);
	UINT32 fSize = ftell(policyFile);
	fseek(policyFile, 0L, SEEK_SET);
	char *pBuf = (char *)malloc(fSize);
	UINT32 sz = fread(pBuf, 1, fSize, policyFile);
	fclose(policyFile);
	raslr_assert(sz, "Cannot read any byte\n");

	UINT32 index = 0;
	UINT32 pCount = *(UINT32 *)pBuf;
	index += sizeof(UINT32);

	// load policies to taintPolicies list
	for (UINT32 i = 0; i < pCount; ++i) {
		TaintPolicy *tp = (TaintPolicy *)(pBuf + index);
		index += sizeof(TaintPolicy);
		taintPolicies.push_back(tp);
		taintOpcs.insert(tp->opc);

#ifdef USE_SUB_POLICY
		// load sub policies
		tp->subPolicies = NULL;
		for (UINT32 j = 0; j < tp->subPCount; ++j) {
			SubTaintPolicy *stp = (SubTaintPolicy *)(pBuf + index);
			index += sizeof(SubTaintPolicy);
			stp->next = tp->subPolicies;
			tp->subPolicies = stp; 
		}
#endif
	}

	// find address of mremap() in libc
	void* libc = dlopen("/lib/x86_64-linux-gnu/libc-2.19.so", 
			RTLD_LAZY);
	raslr_mremap = 
		(VOID *(*)(VOID*, size_t, size_t, int, VOID*))dlsym(libc, "mremap");
}

VOID Fini(INT32 code, VOID *v) {
	procMgr->ReleaseMaps();
}

int main(int argc, char *argv[])
{
	cout<<"[raslr] tracking pointers"<<endl;
	PIN_InitSymbols();
	if(PIN_Init(argc, argv)){
		return Usage();
	}
	InitAll();

	// instrument syscalls
	PIN_AddSyscallEntryFunction(SyscallEntry, 0);
	PIN_AddSyscallExitFunction(SyscallExit, 0);

	// instrument instructions and function calls
	IMG_AddInstrumentFunction(ImageLoad, 0);
	INS_AddInstrumentFunction(Instruction, 0);

	PIN_AddDetachFunction(PostDetach, params);

	PIN_AddFiniFunction(Fini, 0);

	// analysis
	PIN_StartProgram();

	return 0;
}
