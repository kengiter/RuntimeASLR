
/*
 * syscall manager: syscall modelling 
 */

#ifndef SYSCALL_MGR_H
#define SYSCALL_MGR_H

#include "raslr.h"
#include "proc_mgr.h"
#include "taint_mgr.h"
#include <asm/prctl.h>

// syscall context
struct SyscallCtx {
	UINT64 num;
	UINT64 arg0;
	UINT64 arg1;
	UINT64 arg2;
	UINT64 arg3;
	UINT64 arg4;
	UINT64 arg5;
	UINT64 ret;
	UINT64 err;
	CONTEXT *ctx;
};

class SyscallMgr {
	public:
		SyscallMgr(ProcMgr *pm, TaintMgr *tm) {
			procMgr = pm;
			taintMgr = tm;
		};

		VOID HandleSyscall(SyscallCtx *sctx);
		VOID arch_prctl(SyscallCtx *sctx);
		VOID munmap(SyscallCtx *sctx);
		VOID mmap(SyscallCtx *sctx);
		VOID mprotect(SyscallCtx *sctx);
		VOID mremap(SyscallCtx *sctx);
		VOID brk(SyscallCtx *sctx);
		VOID open(SyscallCtx *sctx);
		VOID close(SyscallCtx *sctx);


		ProcMgr *procMgr;
		TaintMgr *taintMgr;

		UINT64 oldBrk;
};

UINT64 handledSyscalls[] = {__NR_arch_prctl, 
	__NR_munmap, __NR_mmap, __NR_mremap, __NR_brk,
	__NR_mprotect
};


/* implementation of member functions */
// dispatcher
VOID SyscallMgr::HandleSyscall(SyscallCtx *sctx) {
#ifdef VERBOSE_MODE
	cout<<"syscall="<<dec<<sctx->num<<endl;
#endif
	UINT64 num = sctx->num;
	switch (num) {
		case __NR_arch_prctl:
			arch_prctl(sctx);
			break;
		case __NR_munmap:
			munmap(sctx);
			break;
		case __NR_mmap:
			mmap(sctx);
			break;
		case __NR_mremap:
			mremap(sctx);
			break;
		case __NR_brk:
			brk(sctx);
			break;
		case __NR_mprotect:
			mprotect(sctx);
			break;
		case __NR_open:
			open(sctx);
			break;
		case __NR_close:
			close(sctx);
			break;

		default:
			break;
	}
}


/* different syscall handlers */
// arch_prctl - set architecture-specific thread state
VOID SyscallMgr::arch_prctl(SyscallCtx *sctx) {
	if (taintMgr) {
		UINT64 code = sctx->arg0;
		if (code == ARCH_GET_FS || code == ARCH_GET_GS) {
			UINT64 addr = sctx->arg1;
			if (procMgr->IsValidAddress(*(UINT64 *)addr)) {
				taintMgr->TaintMem(addr);
#ifdef VERBOSE_MODE
				cout<<"[arch_prctl]  taint="<<hex<<addr<<endl;
#endif
			}
		}
	}
}

VOID SyscallMgr::munmap(SyscallCtx *sctx) {
#ifdef VERBOSE_MODE
	cout<<"[munmap] "<<hex<<sctx->arg0<<" - "<<
		sctx->arg0 + sctx->arg1<<endl;
#endif
	procMgr->DeleteMap(sctx->arg0, sctx->arg0 + sctx->arg1);
	if (taintMgr) { 
		taintMgr->UntaintMemRange(sctx->arg0, sctx->arg0 + sctx->arg1);
		taintMgr->UntaintPtrsRange(sctx->arg0, sctx->arg0 + sctx->arg1);
		taintMgr->UntaintRegsRange(sctx->ctx, 
				sctx->arg0, sctx->arg0 + sctx->arg1);
	}
}

VOID SyscallMgr::mmap(SyscallCtx *sctx) {
#ifdef VERBOSE_MODE
	cout<<"[mmap] "<<hex<<sctx->ret<<" - "<<
		sctx->ret + sctx->arg1<<endl;
#endif
	procMgr->AddMap(sctx->ret, sctx->ret + sctx->arg1, sctx->arg2,
			UnknownMap, procMgr->GetFileName(sctx->arg4));
	if (taintMgr)
		taintMgr->TaintReg(REG_RAX);
	if (sctx->arg0 != 0)
		raslr_assert(sctx->ret == sctx->arg0, "mmap ret value\n");
}

VOID SyscallMgr::mprotect(SyscallCtx *sctx) {
#ifdef VERBOSE_MODE
	cout<<"[mprotect] "<<hex<<sctx->arg0<<" - "<<
		sctx->arg0 + sctx->arg1<<endl;
#endif
	if (sctx->ret == 0) 
		procMgr->AddMap(sctx->arg0, sctx->arg0 + sctx->arg1, sctx->arg2);
	// TODO: update tainted ptrs, if prot is changed
}

VOID SyscallMgr::mremap(SyscallCtx *sctx) {
#ifdef VERBOSE_MODE
	cout<<"[mremap] "<<hex<<sctx->arg0<<" - "<<
		sctx->arg0 + sctx->arg1<<endl;
#endif
	procMgr->DeleteMap(sctx->arg0, sctx->arg0 + sctx->arg1);
	procMgr->AddMap(sctx->ret, sctx->ret + sctx->arg1, sctx->arg2,
			UnknownMap, procMgr->GetFileName(sctx->arg4));
	if (taintMgr)
		taintMgr->TaintReg(REG_RAX);
}

VOID SyscallMgr::brk(SyscallCtx *sctx) {
#ifdef VERBOSE_MODE
	cout<<"[brk] "<<hex<<oldBrk<<" - "<<
		sctx->arg0<<endl;
#endif
	// sbrk(0) is to get current memory break
	if (sctx->arg0 == 0)
		oldBrk = sctx->ret;
	else {
		raslr_assert(oldBrk, "Cannot get old brk\n");
		procMgr->AddMap(oldBrk, sctx->arg0, PROT_READ|PROT_WRITE, 
				HeapMap);
		if (taintMgr) {
			//taintMgr->TaintReg(REG_RAX);
			taintMgr->TaintReg(REG_RBX);
		}

		// if it is shrinking
		mapping *map = procMgr->FindMap(sctx->arg0);
		if (map) {
			procMgr->DeleteMap(sctx->arg0, map->end);
			if (taintMgr) { 
				taintMgr->UntaintMemRange(sctx->arg0, map->end + 1);
				taintMgr->UntaintPtrsRange(sctx->arg0, map->end + 1);
				taintMgr->UntaintRegsRange(sctx->ctx,
						sctx->arg0, map->end + 1);
			}
		}
	}
	if (taintMgr) 
		taintMgr->TaintReg(REG_RAX);
}


VOID SyscallMgr::open(SyscallCtx *sctx) {
	FileObj fo;
	fo.fd = sctx->ret;
	strcpy(fo.fn, (char *)(sctx->arg0));
	procMgr->fileObjs.insert(fo);
}


VOID SyscallMgr::close(SyscallCtx *sctx) {
	FileObj fo;
	fo.fd = sctx->arg0;
	procMgr->fileObjs.erase(fo);
}

#endif
