
/*
 * taint_mgr: tainting and untainting memory and registers 
 */

#ifndef TAINT_MGR_H
#define TAINT_MGR_H

#include <set>
#include "utils.h"
#include "proc_mgr.h"
#include "raslr.h"

#define NUM_GENERAL_REG 16

// information of a tainted pointer
struct TaintedPtr {
	UINT64 addr;
	UINT64 base;
	UINT8 taint;
	bool operator < (const TaintedPtr &other) const { return addr < other.addr; }
	bool operator > (const TaintedPtr &other) const { return addr > other.addr; }
	bool operator = (const TaintedPtr &other) const { return addr == other.addr; }
};

// taint manager
class TaintMgr {
	public:
		TaintMgr(ProcMgr *pm) {
			memset(taintedRegs, 0, sizeof(taintedRegs));
			TaintReg(REG_RIP);
			TaintReg(REG_EIP);
			TaintReg(REG_RSP);
			TaintReg(REG_ESP);

			procMgr = pm;
		};

		VOID TaintInitPtrs(CONTEXT *ctx);
		VOID TaintReg(REG reg, UINT8 taint = 1);
		VOID UntaintReg(REG reg);
		VOID UntaintMem(UINT64 addr);
		VOID TaintMem(UINT64 addr, UINT8 taint = 1);
		VOID UntaintMemRange(UINT64 start, UINT64 end);
		VOID UntaintPtrsRange(UINT64 start, UINT64 end);
		VOID UntaintRegsRange(CONTEXT *ctx, UINT64 start, UINT64 end);
		VOID UpdateMemRange(UINT64 start, UINT64 end, 
				UINT64 offset);
		VOID UpdatePtrsRange(UINT64 start, UINT64 end, 
				UINT64 offset, UINT64 mangleKey = 0);
		VOID UpdateRegsRange(UINT64 **regRefs,
				UINT64 start, UINT64 end, UINT64 offset);
		VOID UpdateRegsRange(CONTEXT *ctx,
				UINT64 start, UINT64 end, UINT64 offset);

		UINT8 GetRegTaint(REG reg) { 
			return taintedRegs[utils::GetFullReg(reg)]; 
		}
		UINT8 GetMemTaint(UINT64 addr) {
			TaintedPtr tp; tp.addr = addr;
			set<TaintedPtr>::iterator it = taintedPtrs.find(tp);
			if (it == taintedPtrs.end())
				return 0;
			else
				return it->taint;
		}

		VOID PrintTaintedPtrs(CONTEXT *ctx);
		VOID PrintTaintedRegs(CONTEXT *ctx);

		VOID PostPtrPruning(CONTEXT *ctx);
		VOID CheckFalseNegatives(UINT64 stackBase, UINT64 curStack);

		set<TaintedPtr>taintedPtrs;
		UINT8 taintedRegs[REG_LAST + 1];


		ProcMgr *procMgr;
};





/* implementation of member functions */

// taint initial pointers prepared by OS
VOID TaintMgr::TaintInitPtrs(CONTEXT *ctx) {
	// taint initial regs
	for (UINT32 i = 0; i < REG_LAST; ++i) {
		if (REG_is_gr((REG)i)) {
			UINT64 regV = PIN_GetContextReg(ctx, (REG)i);
			if (procMgr->IsValidAddress(regV)) {
				TaintReg((REG)i);
			}
		}
	}

	// taint initial pointers in memory
	mapping *iter = procMgr->maps;
	while(iter) {
		if (((iter->protI)&PROT_READ) && !((iter->protI)&PROT_EXEC)) {
			for (UINT64 addr = iter->start; addr < iter->end - 8; ++addr) {
				UINT64 mem = *(UINT64 *)addr;
				if (mem > MAX_ADDRESS || mem < MIN_ADDRESS)
					continue;
				if (procMgr->IsValidAddress(mem)) {
					// taint the address
					TaintMem(addr);
#ifdef VERBOSE_MODE
					cout<<"Init Ptr: *"<<hex<<addr<<"="<<mem<<endl;
#endif
				}
			}
		}
		iter = iter->next;
	}
}

/* Tainting and untainting */
VOID TaintMgr::UntaintMem(UINT64 addr)
{
	TaintedPtr tp;
	tp.addr = addr;
	taintedPtrs.erase(tp);
#ifdef PRINT_INFO
	cout << hex << "\t\t\t" << addr << " is now freed" << endl;
#endif
}

VOID TaintMgr::TaintMem(UINT64 addr, UINT8 taint)
{
	TaintedPtr tp;
	tp.addr = addr;
	tp.taint = taint;
	taintedPtrs.insert(tp);
#ifdef PRINT_INFO
	cout << hex << "\t\t\t" << addr << " is now tainted" << endl;
#endif
}

VOID TaintMgr::TaintReg(REG reg, UINT8 taint)
{
	taintedRegs[utils::GetFullReg(reg)] = taint;
#ifdef PRINT_DEBUG
	cout << "@ TaintReg=" << REG_StringShort(reg) << endl;
#endif
#ifdef PRINT_INFO
	cout << "\t\t\t" << REG_StringShort(reg) << " is now tainted" << endl;
#endif
}

VOID TaintMgr::UntaintReg(REG reg)
{
	taintedRegs[utils::GetFullReg(reg)] = 0;
#ifdef PRINT_DEBUG
	cout << "@ UntaintReg=" << REG_StringShort(reg) << endl;
#endif
#ifdef PRINT_INFO
	cout << "\t\t\t" << REG_StringShort(reg) << " is now freed" << endl;
#endif
}

VOID TaintMgr::UntaintMemRange(UINT64 start, UINT64 end)
{
	std::set<TaintedPtr>::iterator itStart = taintedPtrs.end(), 
		itEnd = taintedPtrs.end();
	for (std::set<TaintedPtr>::iterator it = taintedPtrs.begin(); 
			it != taintedPtrs.end(); ++it) {
		if (it->addr > end)
			break;
		if (it->addr >= start && itStart == taintedPtrs.end())
			itStart = it;
		if (it->addr <= end)
			itEnd = it;
	}
	if (itStart != taintedPtrs.end() && 
			itEnd != taintedPtrs.end()) {
		taintedPtrs.erase(itStart, ++itEnd);
	}
#ifdef PRINT_INFO
	cout << hex << "\t\t\t" << "<"<<start<<", "
		<<end<<"> is now freed" << endl;
#endif
}

VOID TaintMgr::UntaintPtrsRange(UINT64 start, UINT64 end)
{
	//raslr_assert(end >= start, "end < start in untaint ptr range\n");
	std::set<TaintedPtr>::iterator it = taintedPtrs.begin();
	std::set<TaintedPtr>::iterator itTmp;
	while (it != taintedPtrs.end()) {
		//for (std::set<TaintedPtr>::iterator it = taintedPtrs.begin(); 
		//    it != taintedPtrs.end(); ++it) {
		UINT64 mem = *(UINT64 *)it->addr;
		itTmp = it; 
		++it;
		if (mem >= start && mem < end)
			taintedPtrs.erase(itTmp);
	}
	}

	VOID TaintMgr::UntaintRegsRange(CONTEXT *ctx,
			UINT64 start, UINT64 end) {
		for (UINT32 i = 0; i < REG_LAST; ++i) {
			REG reg = (REG)i;
			if (REG_is_gr(reg) || reg == REG_RIP) {
				UINT64 regV = PIN_GetContextReg(ctx, reg);
				if (start <= regV && regV < end)
					UntaintReg(reg);
			}
		}
	}

	VOID TaintMgr::UpdateMemRange(UINT64 start, UINT64 end, 
			UINT64 offset) {
		std::set<TaintedPtr>::iterator it = taintedPtrs.begin();
		std::set<TaintedPtr>::iterator itTmp;
		while (it != taintedPtrs.end()) {
			itTmp = it; 
			++it;
			if (itTmp->addr >= start && itTmp->addr < end) {
				TaintedPtr tp;
				tp.addr = itTmp->addr + offset;
				taintedPtrs.erase(itTmp);
				taintedPtrs.insert(tp);
			}
		}
	}

	VOID TaintMgr::UpdatePtrsRange(UINT64 start, UINT64 end,
			UINT64 offset, UINT64 mangleKey)
	{
		raslr_assert(end >= start, "end < start in update ptr range\n");
		mapping *curMap = NULL;
		BOOL curProtChanged = false;
		for (std::set<TaintedPtr>::iterator it = taintedPtrs.begin(); 
				it != taintedPtrs.end(); ++it) {
			UINT64 ptr = 0;
			if (it->taint == 2) {
				ptr = utils::Demangle(*(UINT64 *)it->addr, mangleKey);
			}
			else 
				ptr = *(UINT64 *)(it->addr);
			if (ptr >= start && ptr < end) {
				// make sure it is writable
				if (!curMap || (it->addr < curMap->start || 
							it->addr >= curMap->end)) {
					if (curProtChanged) {
						mprotect((void *)curMap->start, curMap->end - curMap->start, 
								curMap->protI);
						curProtChanged = false;
					}
					curMap = procMgr->FindMap(it->addr);
					if (!(curMap->protI&PROT_WRITE)) {
						mprotect((void *)curMap->start, curMap->end - curMap->start, 
								(curMap->protI|PROT_WRITE));
						curProtChanged = true;
					}
				}
				// do patching
				if (it->taint == 2)
					ptr = utils::Mangle(ptr + offset, mangleKey);
				else 
					ptr += offset;
				*(UINT64 *)(it->addr) = ptr;
			}
		}
	}

	VOID TaintMgr::UpdateRegsRange(UINT64 **regRefs,
			UINT64 start, UINT64 end, UINT64 offset) {
		for (UINT32 i = 0; i < NUM_GENERAL_REG; ++i) {
			if (start <= *(regRefs[i]) && *(regRefs[i]) < end)
				*(regRefs[i]) += offset;
		}
	}

	VOID TaintMgr::UpdateRegsRange(CONTEXT *ctx,
			UINT64 start, UINT64 end, UINT64 offset) {
		for (UINT32 i = 0; i < REG_LAST; ++i) {
			REG reg = (REG)i;
			if (REG_is_gr(reg) || reg == REG_RIP) {
				UINT64 regV = PIN_GetContextReg(ctx, reg);
				if (start <= regV && regV < end)
					PIN_SetContextReg(ctx, reg, regV + offset);
			}
		}
		UINT64 fsV = PIN_GetContextReg(ctx, REG_SEG_FS_BASE);
		if (start <= fsV && fsV < end)
			PIN_SetContextReg(ctx, REG_SEG_FS_BASE, 
					fsV + offset);
	}

	VOID TaintMgr::PrintTaintedPtrs(CONTEXT *ctx) {
		for (set<TaintedPtr>::iterator it=taintedPtrs.begin(); 
				it!=taintedPtrs.end(); ++it) {
			cout<<hex<<"*"<<it->addr<<"="<<*(UINT64*)it->addr<<endl;
			if (it->taint == 2)
				cout<<"mangle pointer"<<endl;
			if (!procMgr->IsValidAddress(*(UINT64*)it->addr) &&
					!procMgr->IsMangledAddress(*(UINT64*)it->addr, ctx)) {
				// FIXME: Pin may modify some initial pointers, which cannot
				// be tracked, so filter them out here?
				cout<<"@ FP Ptr *"<<hex<<it->addr<<"="<<*(UINT64*)it->addr<<endl;
			}
		}
	}

	VOID TaintMgr::PostPtrPruning(CONTEXT *ctx) {
		set<TaintedPtr>::iterator it = taintedPtrs.begin();
		set<TaintedPtr>::iterator itTmp;
		while (it != taintedPtrs.end()) {
			if (!procMgr->IsValidAddress(*(UINT64*)it->addr) &&
					!procMgr->IsMangledAddress(*(UINT64*)it->addr, ctx)) {
				// FIXME: Pin may modify some initial pointers, which cannot
				// be tracked, so filter them out here?
				cout<<"@ FP Ptr *"<<hex<<it->addr<<"="<<*(UINT64*)it->addr<<endl;
				itTmp = it;
				++it;
				taintedPtrs.erase(itTmp);
			}
			else
				++it;
		}
	}

	VOID TaintMgr::CheckFalseNegatives(UINT64 stackBase, UINT64 curStack) {
		mapping *it = procMgr->maps;
		while(it) {
			if (it->mapType == SharedMap) {
				it = it->next;
				continue;
			}
			if (((it->protI)&PROT_READ) && !((it->protI)&PROT_EXEC) 
				 ) {
				if (it->mapType == StackMap)
					cout<<"checking stack map"<<endl;
				else if (it->mapType == HeapMap)
					cout<<"checking heap map"<<endl;
				else
					cout<<"checking other maps"<<endl;
				for (UINT64 addr = it->start; addr < it->end - 8; ++addr) {
					if (it->mapType == StackMap) {
						if (stackBase <= addr && addr < curStack)
							continue;
					}
					else if (it->mapType == HeapMap) {
						if (!procMgr->IsHeapObjAddress(addr))
							continue;
					}
					UINT64 mem = *(UINT64 *)addr;
					if (mem > MAX_ADDRESS || mem < MIN_ADDRESS)
						continue;
					if (procMgr->IsValidAddress(mem)) {
						// false negative
						if (GetMemTaint(addr) == 0) {
							cout<<"@ FN: *"<<hex<<addr<<"="<<mem<<endl;
						}
					}
				}
			}
			it = it->next;
		}
	}

	VOID TaintMgr::PrintTaintedRegs(CONTEXT *ctx) {
		for (UINT32 i = 0; i < REG_LAST; ++i) {
			if (taintedRegs[i])
				cout<<REG_StringShort((REG)i)<<"="<<hex<<
					PIN_GetContextReg(ctx, (REG)i)<<endl;
		}
		cout<<"fs="<<hex<<PIN_GetContextReg(ctx, REG_SEG_FS_BASE)<<endl;
	}


#endif
