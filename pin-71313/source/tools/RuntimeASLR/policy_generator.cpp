/*
 * Automated pointer tracking policy generator
 *
 * x86_64 only
 * The target program is supposed to be ASLR-enabled
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
#include "proc_mgr.h"
#include "syscall_mgr.h"
#include "utils.h"
#include "policy_rep.h"

using namespace std;


#if defined(TARGET_MAC)
#define MALLOC "_malloc"
#define FREE "_free"
#else
#define MALLOC "malloc"
#define FREE "free"
#endif


/* global variables */
// key for accessing TLS storage in the threads. 
// Initialized once
static  TLS_KEY tls_key_syscall_ctx;
static  TLS_KEY tls_key_sp;

// tracking policy
list<TaintPolicy *> taintPolicies;

// record syscalls
set<UINT32> syscalls;

// manager instances
ProcMgr *procMgr;
SyscallMgr *syscallMgr;

// base address of stack
UINT64 curStackBase = 0;
// layer of current process
UINT32 forkLayer = 0;

// config the n-run verification
// number of runs
UINT32 nruns = 0;
// nth run
UINT32 nrun = 0;

// verified taintness (i.e., pointer)
list<TaintVerification *>taintVerifications;
list<TaintVerification *>::iterator curVer;

/* extract the inputs (e.g., taintness of 
 * its operands) of ins */
VOID GetInsInputs(CONTEXT *ctx, InsRep *rep, 
#ifdef SUB_POLICY_LOC
		UINT64 insAddr,
#endif
		UINT64 addrR0 = 0, UINT32 readSize0 = 0, 
		UINT64 addrW = 0, UINT32 writeSize = 0
#ifdef HANDLE_MEM_READ2
		, UINT64 addrR1 = 0, UINT32 readSize1 = 0
#endif
		) { 
	// initialization
	rep->taintsInR = 0;
	rep->taintsInW = 0;
#ifdef SUB_POLICY_HIBIT
	memset(rep->hiBits, 0, 8);
#endif

	UINT8 *tir = (UINT8 *)&(rep->taintsInR);
	UINT8 *tiw = (UINT8 *)&(rep->taintsInW);
	BOOL isFirstMemRead = true;
	// check if the operand is an address
	for (UINT8 i = 0; i < rep->opeCount; ++i) {
		BOOL isRead = (((rep->opeRead)>>i)&1);
		BOOL isWritten = (((rep->opeWritten)>>i)&1);
		UINT8 opeT = ((rep->opeTypes)>>(i*4))&0xf;
		UINT8 opeWidth = ((UINT8 *)&(rep->opeWidths))[i];
		if (opeT == OpeTypeReg) {
			// only consider general purpose regs
			REG fullReg = utils::GetFullReg((REG)(rep->opeData[i]));
			// FIXME: how about non-general regs?
			if (REG_is_gr64(fullReg)) {
				UINT64 regV = PIN_GetContextReg(ctx, fullReg);
				if (procMgr->IsValidAddress(regV)) {
					// each byte indicates the reg is an address or not
					if (isRead)
						tir[i] = 1;
					if (isWritten) 
						tiw[i] = 1;
				}
				else if (procMgr->IsMangledAddress(regV, ctx)) {
					if (isRead)
						tir[i] = 2;
					if (isWritten) 
						tiw[i] = 2;
				}
#ifdef SUB_POLICY_HIBIT
				// get the highest bit
				if (isRead)
					rep->hiBits[i] = utils::HiBit(regV);

#endif
#ifdef PRINT_VALUE
				// testing
				cout<<hex<<REG_StringShort(fullReg)<<"="<<regV<<endl;
#endif
			}
			else if (opeWidth == 128) {
				UINT64* regP = new UINT64[2];
				PIN_GetContextRegval(ctx, fullReg, (UINT8 *)regP);
				// check first 64-bits
				if (procMgr->IsValidAddress(regP[0])) {
					if (isRead)
						tir[i] = 1;
					if (isWritten) 
						tiw[i] = 1;
				}
				// check second 64-bits
				else if (procMgr->IsValidAddress(regP[1])) {
					if (isRead)
						tir[i] |= 1<<4;
					if (isWritten) 
						tiw[i] |= 1<<4;
				}
#ifdef SUB_POLICY_HIBIT
				if (isRead)
					rep->hiBits[i] = utils::HiBit(regP[0]);
#endif
			}
		}
		else if (opeT == OpeTypeMem) {
			UINT64 addr = 0;
			if (isRead) {
				if (isFirstMemRead) {
					addr = addrR0;
					isFirstMemRead = false;
				}
#ifdef HANDLE_MEM_READ2
				else { 
					addr = addrR1;
				}
#endif
				if (opeWidth == 64) {
					if (procMgr->IsValidAddress(*(UINT64 *)addr))
						tir[i] = 1;
					else if (procMgr->IsMangledAddress(*(UINT64 *)addr,
								ctx))
						tir[i] = 2;

#ifdef PRINT_VALUE
					// testing
					cout<<hex<<"*"<<addr<<"="<<*(UINT64 *)addr<<endl;
#endif
				}
				// for float ope
				else if (opeWidth == 128) {
					if (procMgr->IsValidAddress(*(UINT64 *)addr))
						tir[i] = 1;
					else if (procMgr->IsValidAddress(*(UINT64 *)(addr + 8)))
						tir[i] |= 1<<4;
				}
#ifdef SUB_POLICY_HIBIT
				if (opeWidth == 64 || opeWidth == 128)
					rep->hiBits[i] = utils::HiBit(*(UINT64 *)addr);
#endif
			}
			if (isWritten) {
				if (opeWidth != 128) {
					if (procMgr->IsValidAddress(*(UINT64 *)addrW))
						tiw[i] = 1;
					else if (procMgr->IsMangledAddress(*(UINT64 *)addrW,
								ctx))
						tiw[i] = 2;
				}
				else if (opeWidth == 128) {
					if (procMgr->IsValidAddress(*(UINT64 *)addrW))
						tiw[i] = 1;
					else if (procMgr->IsValidAddress(*(UINT64 *)(addrW + 8)))
						tiw[i] |= 1<<4;
				}
				rep->toWriteAddr = addrW;
			}
		}
		else if (opeT == OpeTypeImm) {
			if (procMgr->IsValidAddress(rep->opeData[i]))
				tir[i] = 1;
#ifdef SUB_POLICY_HIBIT
			rep->hiBits[i] = utils::HiBit(rep->opeData[i]);
#endif
		}
		//else
		//  raslr_not_reachable();
	}

	/* n-run pointer verification */
	if (nrun == 1) {
		TaintVerification *taintVer = new TaintVerification();
		taintVer->insSeq = rep->insSeq;
		taintVer->taintsIn = (rep->taintsInR | rep->taintsInW);
		taintVerifications.push_back(taintVer);
	}
	else {
		for (; curVer != taintVerifications.end(); ++curVer) {
			if ((*curVer)->insSeq == rep->insSeq) {
				(*curVer)->taintsIn &= (rep->taintsInR | rep->taintsInW);
				rep->taintsInR &= (*curVer)->taintsIn;
				rep->taintsInW &= (*curVer)->taintsIn;
				break;
			}
		}
	}

#ifdef SUB_POLICY_LOC
	mapping *map = procMgr->FindMap(insAddr);
	char *name = strrchr(map->objFile, '/');
	name = (name == NULL? map->objFile : name);
	strcpy(rep->module, name);
	rep->offset = insAddr - map->start;
#endif
}

/* extract output taintnesses of the ins */
VOID GetInsOutputs(CONTEXT *ctx, InsRep *rep, 
		UINT64 addrW = 0, UINT32 writeSize = 0) {
	// initialization
	rep->taintsOut = 0;
	UINT8 *to = (UINT8 *)&(rep->taintsOut);
	for (UINT8 i = 0; i < rep->opeCount; ++i) {
		// only consider written opes
		if (!(((rep->opeWritten)>>i)&1))
			continue;

		UINT8 opeWidth = ((UINT8 *)&(rep->opeWidths))[i];
		UINT8 opeT = ((rep->opeTypes)>>(i*4))&0xf;
		if (opeT == OpeTypeReg) {
			REG fullReg = utils::GetFullReg((REG)(rep->opeData[i]));
			// FIXME: how about non-general regs?
			if (REG_is_gr64(fullReg)) {
				UINT64 regV = PIN_GetContextReg(ctx, fullReg);
				if (procMgr->IsValidAddress(regV)) {
					to[i] = 1;
				}
				else if (procMgr->IsMangledAddress(regV, ctx))
					to[i] = 2;
#ifdef PRINT_VALUE
				//testing
				cout<<"--"<<endl<<hex<<REG_StringShort(fullReg)<<"="<<regV<<endl;
#endif
			}
			// float ope
			else if (opeWidth == 128) {
				UINT64* regP = new UINT64[2];
				PIN_GetContextRegval(ctx, fullReg, (UINT8 *)regP);
				// check first 64-bit
				if (procMgr->IsValidAddress(regP[0])) 
					to[i] = 1;
				else if (procMgr->IsValidAddress(regP[1]))
					to[i] |= 1<<4;
			}
		}
		else if (opeT == OpeTypeMem) {
			if (opeWidth != 128) {
				if (procMgr->IsValidAddress(*(UINT64 *)(rep->toWriteAddr))) {
					to[i] = 1;
				}
				else if (procMgr->IsMangledAddress(
							*(UINT64 *)(rep->toWriteAddr), ctx))
					to[i] = 2;

#ifdef PRINT_VALUE
				//testing
				cout<<"--"<<endl<<hex<<"*"<<rep->toWriteAddr<<"="<<
					*(UINT64 *)(rep->toWriteAddr)<<endl;
#endif
			}
			else if (opeWidth == 128) {
				if (procMgr->IsValidAddress(*(UINT64 *)(rep->toWriteAddr)))
					to[i] = 1;
				else if (procMgr->IsValidAddress(*(UINT64 *)
							(rep->toWriteAddr + 8)))
					to[i] |= 1<<4;
			}
		}
		//else
		//  raslr_not_reachable();
	}

	/* n-run pointer verification */
	if (nrun == 1) {
		TaintVerification *taintVer = taintVerifications.back();
		taintVer->taintsOut = rep->taintsOut;
	}
	else {
		for (; curVer != taintVerifications.end(); ++curVer) {
			if ((*curVer)->insSeq == rep->insSeq) {
				(*curVer)->taintsOut &= rep->taintsOut;
				rep->taintsOut = (*curVer)->taintsOut;
				break;
			}
		}
	}

	TaintPolicy *tp = new TaintPolicy(rep);
	TaintPolicy *etp = FindPolicy(taintPolicies, tp);
	if (!etp) {
		taintPolicies.push_back(tp);

#ifdef VERBOSE_MODE
		cout<<"NEW Policy: "<<rep->dis<<
			" in="<<(UINT32)rep->taintsInR<<
			" out="<<(UINT32)rep->taintsOut<<endl;
#endif
	}
	else {
#ifndef USE_SUB_POLICY
		if (etp->taintsOut != tp->taintsOut) { 
			etp->flags |= ((etp->taintsOut)^(tp->taintsOut));

#ifdef VERBOSE_MODE
			string dis = string(etp->dis);
			cout<<"IMPLICIT: "<<rep->dis<<
				" in="<<(UINT32)rep->taintsInR<<
				" out="<<(UINT32)rep->taintsOut<<
				" | "<<dis<<
				" in="<<(UINT32)etp->taintsIn<<
				" out="<<(UINT32)etp->taintsOut<<endl;
#endif
		}
#else
		// use sub policies
		BOOL toAddSubPolicy = false;
		if (etp->subPCount > 0) {
			toAddSubPolicy = true;
		}
		// first sub policy
		else if (etp->taintsOut != tp->taintsOut) {
			toAddSubPolicy = true;
#ifdef SUB_POLICY_HIBIT
			SubTaintPolicy *stp = new SubTaintPolicy(etp->hiBits);
#endif
#ifdef SUB_POLICY_LOC
			SubTaintPolicy *stp = new SubTaintPolicy(etp->module, 
					etp->offset);
#endif
			stp->taintsOut = etp->taintsOut;
			etp->subPolicies = stp;
			etp->subPCount = 1;
			// no longer useful
			etp->taintsOut = 0;
		}
		if (toAddSubPolicy) {
			etp->flags |= ((etp->taintsOut)^(tp->taintsOut));

#ifdef SUB_POLICY_HIBIT
			SubTaintPolicy *stp = new SubTaintPolicy(rep->hiBits, 
					rep->opeCount);
			SubTaintPolicy *estp = FindSubPolicy(etp->subPolicies, 
					stp->hiBits, rep->opeCount);
#endif
#ifdef SUB_POLICY_LOC
			SubTaintPolicy *stp = new SubTaintPolicy(tp->module,
					tp->offset);
			SubTaintPolicy *estp = FindSubPolicy(etp->subPolicies, 
					stp);
#endif
			stp->taintsOut = tp->taintsOut;
			if (!estp) {
				stp->next = etp->subPolicies;
				etp->subPolicies = stp;
				etp->subPCount += 1;
			}
			else {
				if (estp->taintsOut != stp->taintsOut) { 
					estp->flags |= ((estp->taintsOut)^(stp->taintsOut));

#ifdef VERBOSE_MODE
					string dis = string(etp->dis);
					cout<<"IMPLICIT: "<<rep->dis<<
#ifdef SUB_POLICY_LOC
						" module="<<stp->module<<
						" offset="<<stp->offset<<
#endif
						" in="<<(UINT32)rep->taintsInR<<
						" out="<<(UINT32)rep->taintsOut<<
						" | "<<dis<<
#ifdef SUB_POLICY_LOC
						" module="<<estp->module<<
						" offset="<<estp->offset<<
#endif
						" in="<<(UINT32)etp->taintsIn<<
						" out="<<(UINT32)estp->taintsOut<<endl;
#endif
				}
			}
		}
#endif
	}
}

// dedicated for call ins
VOID GetCallInsOutputs(InsRep *rep) {
	// initialization
	rep->taintsOut = 0;
	UINT8 *to = (UINT8 *)&(rep->taintsOut);
	for (UINT8 i = 0; i < rep->opeCount; ++i) {
		if (((rep->opeRead)>>i)&1)
			continue;
		UINT8 opeT = ((rep->opeTypes)>>(i*4))&0xf;
		if (opeT == OpeTypeMem) {
			if (!(((rep->taintsInW)>>i)&1)) {
				to[i] = 1;
				break;
			}
		}
	}
	// has taintness changed
	if (rep->taintsOut) {
		TaintPolicy *tp = new TaintPolicy(rep);
		TaintPolicy *etp = FindPolicy(taintPolicies, tp);
		if (!etp) 
			taintPolicies.push_back(tp);
		else {
			if (etp->taintsOut != tp->taintsOut) {
				etp->flags |= (etp->taintsOut^tp->taintsOut);
			}
		}
	}
}

/* output taint policy and verifications */
// output taint policy
VOID ExportTaintPolicy() {
	FILE *log = freopen(readablePolicyPath,"wb+", stdout);
	raslr_assert(log, "Cannot create log file\n");
	// output policies to "taint.policy"
	FILE *policyFile = fopen(policyFilePath, "wb");
	raslr_assert(policyFile, "cannot open file");
	UINT32 count = taintPolicies.size();
	fwrite(&count, sizeof(UINT32), 1, policyFile);
	UINT32 i = 0;
	for (list<TaintPolicy *>::iterator it = taintPolicies.begin(); 
			it != taintPolicies.end(); ++it) {
		++i;
		TaintPolicy *tp = *it;
		fwrite(&(*tp), sizeof(TaintPolicy), 1, policyFile);

		// 
		cout<<dec<<i<<". "
#ifdef VERBOSE_MODE
			string dis(tp->dis);
		cout<<"\""<<dis<<"\""
#endif
			<<" opcode="<<tp->opc<<hex
			<<" taintsInR="<<(UINT32)tp->taintsIn
			<<" opeTypes="<<(UINT32)tp->opeTypes
			<<" opeWidths="<<(UINT64)tp->opeWidths
			<<" taintsOut="<<(UINT32)tp->taintsOut
			<<" flags="<<(UINT32)tp->flags;
		if (((UINT8)(tp->flags)) > 0)
			cout<<" [Implicit] "<<endl;
		else
			cout<<endl;

#ifdef USE_SUB_POLICY
		if (tp->subPCount > 0) {
			SubTaintPolicy *stp = tp->subPolicies;
			while (stp) {
				fwrite(stp, sizeof(SubTaintPolicy), 1, policyFile);
				//
#ifdef SUB_POLICY_HIBIT
				cout<<"   hiBits=";
				for (int i = 0; i < 8; ++i) {
					cout<<hex<<(UINT32)(stp->hiBits[i])<<" ";
				}
#endif
#ifdef SUB_POLICY_LOC
				cout<<"module="<<stp->module<<
					" offset="<<hex<<stp->offset;
#endif
				cout<<";  taintsOut="<<stp->taintsOut<<
					" flags="<<stp->flags<<endl;
				if (((UINT8)(stp->flags)) > 0) { 
					cout<<"   || [Implicit] "<<endl;
				}
				SubTaintPolicy *tmp = stp;
				stp = stp->next;
				delete tmp;
			}
		}
#endif
		delete tp;
	}
	fclose(policyFile);
	for(set<UINT32>::iterator it = syscalls.begin(); 
			it != syscalls.end(); it++){
#ifdef VERBOSE_MODE
		cout<<"syscall="<<dec<<*it<<endl;
#endif
	}
}

// output pointer verifications 
VOID ExportTaintVerification() {
	FILE *taintVerFile = fopen(taintVerPath, "wb");
	raslr_assert(taintVerFile, "cannot open file");
	UINT32 count = taintVerifications.size();
	fwrite(&count, sizeof(UINT32), 1, taintVerFile);
	UINT32 i = 0;
	for (list<TaintVerification *>::iterator it = 
			taintVerifications.begin(); 
			it != taintVerifications.end(); ++it) {
		++i;
		TaintVerification *tv = *it;
		fwrite(&(*tv), sizeof(TaintVerification), 1, taintVerFile);
	}
	fclose(taintVerFile);
}

// initialization at first ins
BOOL isFollowClone = false;
BOOL isFirstIns = true;
VOID InitAtFirstIns(CONTEXT *ctx) {
	// image info can only be read when
	// the program is started
	procMgr->LoadInitMaps(ctx);
	FILE *log = freopen(logFilePath,"wb", stdout);
	raslr_assert(log, "Cannot create log file\n");
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
}

// re-randomization right after clone syscall
VOID CloneExit(CONTEXT *ctx) {
	UINT64 pid = PIN_GetContextReg(ctx, REG_RAX);
	if (pid == 0) {
		++forkLayer;
		if (forkLayer == RAND_FORK_LAYER) {
			// dump taint policy to file, when it is
			// the last run
			if (nrun == nruns)
				ExportTaintPolicy();
			// export pointer verifications
			ExportTaintVerification();

			// detach pin
			cout<<"[raslr] Detach Pin at layer "<<forkLayer<<endl;
			PIN_Detach();
		}
	}
	else 
		cout<<"[raslr] Parent process at layer "<<forkLayer<<endl;
}

VOID HandleRetIns (UINT64 addrR) {
	UINT64 *sp = static_cast<UINT64*>(
			PIN_GetThreadData(tls_key_sp, PIN_ThreadId()));
	if (!sp) {
		sp = new UINT64(0);
		PIN_SetThreadData(tls_key_sp, sp, PIN_ThreadId());
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
}

VOID HandleStackPivotIns(CONTEXT *ctx) {
	UINT64 *sp = static_cast<UINT64*>(
			PIN_GetThreadData(tls_key_sp, PIN_ThreadId()));
	if (!sp) {
		sp = new UINT64(PIN_GetContextReg(ctx, REG_RSP));
		PIN_SetThreadData(tls_key_sp, sp, PIN_ThreadId());
	}
	else
		*sp = PIN_GetContextReg(ctx, REG_RSP);
}


/* Instrumentation */
// do tainting and taint propagation
VOID Instruction(INS ins, VOID *v)
{

	if (isFirstIns) {
		INS_InsertCall(
				ins, IPOINT_BEFORE, (AFUNPTR)InitAtFirstIns,
				IARG_CONST_CONTEXT, 
				IARG_END);
		isFirstIns = false;
	}

#ifdef PRINT_DEBUG
	INS_InsertCall(
			ins, IPOINT_BEFORE, (AFUNPTR)utils::PrintIns,
			IARG_PTR, new string(INS_Disassemble(ins)),
			IARG_ADDRINT, INS_Address(ins),
			IARG_END);
#endif

	// filtering
	OPCODE opc = INS_Opcode (ins);

	if (INS_IsSyscall(ins)) {
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
				IARG_CONST_CONTEXT, 
				IARG_END);
		isFollowClone = false;
	}
	else if (INS_IsRet(ins)) {
		INS_InsertCall(
				ins, IPOINT_BEFORE, (AFUNPTR)HandleRetIns,
				IARG_MEMORYOP_EA, 0,
				IARG_END);
	}
	// stack pivot
	else if (INS_IsSub(ins) && 
			INS_OperandIsImmediate(ins, 1) &&
			INS_OperandReg(ins, 0) == REG_RSP) {
		INS_InsertCall(
				ins, IPOINT_AFTER, (AFUNPTR)HandleStackPivotIns,
				IARG_CONST_CONTEXT, 
				IARG_END);
	}

	if (
			INS_HasMemoryRead2(ins) || 
			opc ==  XED_ICLASS_STOSB ||
			INS_IsRet(ins) ||
			INS_IsBranch(ins) ||
			INS_IsSyscall(ins)
		 )
		return;
	raslr_assert(INS_MemoryOperandCount(ins) <= 2, 
			"mem op num > 2");
	// the instrumented ins must modify something
	if (!utils::HasPtrWritten(ins))
		return;

	// do instrumentations
	InsRep *rep = new InsRep(ins);
	if (!INS_IsMemoryRead(ins) && !INS_IsMemoryWrite(ins)) {
		INS_InsertCall(
				ins, IPOINT_BEFORE, (AFUNPTR)GetInsInputs,
				IARG_CONST_CONTEXT, 
				IARG_PTR, rep,
#ifdef SUB_POLICY_LOC
				IARG_ADDRINT, INS_Address(ins),
#endif
				IARG_ADDRINT, 0,  // placeholder
				IARG_UINT32, 0,   // placeholder
				IARG_ADDRINT, 0,  // placeholder
				IARG_UINT32, 0,   // placeholder
				IARG_END);
	}
	else if (INS_IsMemoryRead(ins) && !INS_IsMemoryWrite(ins)) {
		INS_InsertCall(
				ins, IPOINT_BEFORE, (AFUNPTR)GetInsInputs,
				IARG_CONST_CONTEXT, 
				IARG_PTR, rep,
#ifdef SUB_POLICY_LOC
				IARG_ADDRINT, INS_Address(ins),
#endif
				IARG_MEMORYOP_EA, 0,
				IARG_UINT32, INS_MemoryReadSize(ins),
				IARG_ADDRINT, 0,  // placeholder
				IARG_UINT32, 0,   // placeholder
				IARG_END);
	}
	else if (!INS_IsMemoryRead(ins) && INS_IsMemoryWrite(ins)) {
		INS_InsertCall(
				ins, IPOINT_BEFORE, (AFUNPTR)GetInsInputs,
				IARG_CONST_CONTEXT, 
				IARG_PTR, rep,
#ifdef SUB_POLICY_LOC
				IARG_ADDRINT, INS_Address(ins),
#endif
				IARG_ADDRINT, 0,  // placeholder
				IARG_UINT32, 0,   // placeholder
				IARG_MEMORYOP_EA, 0,
				IARG_UINT32, INS_MemoryWriteSize(ins),
				IARG_END);
	}
	else {
		INS_InsertCall(
				ins, IPOINT_BEFORE, (AFUNPTR)GetInsInputs,
				IARG_CONST_CONTEXT, 
				IARG_PTR, rep,
#ifdef SUB_POLICY_LOC
				IARG_ADDRINT, INS_Address(ins),
#endif
				IARG_MEMORYOP_EA, INS_MemoryOperandIsRead(ins, 1),
				IARG_UINT32, INS_MemoryReadSize(ins),
				IARG_MEMORYOP_EA, INS_MemoryOperandIsWritten(ins, 1),
				IARG_UINT32, INS_MemoryWriteSize(ins),
				IARG_END);
	}

	if (INS_IsCall(ins)) {
		INS_InsertCall(
				ins, IPOINT_BEFORE, (AFUNPTR)GetCallInsOutputs,
				IARG_PTR, rep,
				IARG_END);
	}
	else {
		if (!INS_IsMemoryWrite(ins)) {
			INS_InsertCall(
					ins, IPOINT_AFTER, (AFUNPTR)GetInsOutputs,
					IARG_CONST_CONTEXT, 
					IARG_PTR, rep,
					IARG_ADDRINT, 0,  // placeholder
					IARG_UINT32, 0,   // placeholder
					IARG_END);
		}
		else {
			INS_InsertCall(
					ins, IPOINT_AFTER, (AFUNPTR)GetInsOutputs,
					IARG_CONST_CONTEXT, 
					IARG_PTR, rep,
					IARG_MEMORYOP_EA, INS_MemoryOperandIsWritten(ins, 1),
					IARG_UINT32, INS_MemoryWriteSize(ins),
					IARG_END);
		}
	}
}

/* handling heap objects */
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
}

VOID FreeBefore(ADDRINT addr)
{
	HeapObj ho;
	ho.addr = addr;
	set<HeapObj>::iterator it = procMgr->heapObjs.find(ho);
	if (it != procMgr->heapObjs.end()) {
		memset((VOID *)addr, 0, it->size);
		procMgr->heapObjs.erase(ho);
	}
}

static VOID ImageLoad(IMG img, VOID * v)
{
	/* Instrument the malloc() and free() functions */
	//  Find the malloc() function.
	RTN mallocRtn = RTN_FindByName(img, MALLOC);
	if (RTN_Valid(mallocRtn))
	{
		RTN_Open(mallocRtn);

		// Instrument malloc() to print the input argument 
		// value and the return value.
		RTN_InsertCall(mallocRtn, IPOINT_BEFORE, (AFUNPTR)MallocBefore,
				IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
				IARG_END);
		RTN_InsertCall(mallocRtn, IPOINT_AFTER, (AFUNPTR)MallocAfter,
				IARG_FUNCRET_EXITPOINT_VALUE, IARG_END);

		RTN_Close(mallocRtn);
	}

	// Find the free() function.
	RTN freeRtn = RTN_FindByName(img, FREE);
	if (RTN_Valid(freeRtn))
	{
		RTN_Open(freeRtn);
		// Instrument free() to print the input argument value.
		RTN_InsertCall(freeRtn, IPOINT_BEFORE, (AFUNPTR)FreeBefore,
				IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
				IARG_END);
		RTN_Close(freeRtn);
	}
}

/* handling syscalls */
VOID SyscallEntry(THREADID thread_id, CONTEXT *ctx, SYSCALL_STANDARD std, void *v)
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

VOID SyscallExit(THREADID thread_id, CONTEXT *ctx, SYSCALL_STANDARD std, void *v)
{
	SyscallCtx *sctx = static_cast<SyscallCtx*>
		(PIN_GetThreadData(tls_key_syscall_ctx, thread_id));
	sctx->ret = PIN_GetSyscallReturn(ctx, std);
	syscallMgr->HandleSyscall(sctx);
	syscalls.insert(sctx->num);
}


////////////////////////////////////
/* main */
INT32 Usage()
{
	cerr << "Automatically generate pointer tracking policies. \n\
		Usage: see run.sh" << endl;
	return -1;
}

VOID InitAll() {
	PIN_SetSyntaxIntel();

	// Obtain  a key for TLS storage.
	tls_key_syscall_ctx = PIN_CreateThreadDataKey(0);
	tls_key_sp = PIN_CreateThreadDataKey(0);

	procMgr = new ProcMgr(getpid());
	syscallMgr = new SyscallMgr(procMgr, NULL);

	// load taint verifications
	if (nrun > 1) {
		FILE *taintVerFile = fopen(taintVerPath, "rb");
		raslr_assert(taintVerFile, "Cannot open taint verification file!");
		fseek(taintVerFile, 0L, SEEK_END);
		UINT32 fSize = ftell(taintVerFile);
		fseek(taintVerFile, 0L, SEEK_SET);
		char *vBuf = (char *)malloc(fSize);
		UINT32 sz = fread(vBuf, 1, fSize, taintVerFile);
		fclose(taintVerFile);
		raslr_assert(sz, "Cannot read any byte\n");

		UINT32 index = 0;
		UINT32 vCount = *(UINT32 *)vBuf;
		index += sizeof(UINT32);

		// load verifications to taintVerifications list
		for (UINT32 i = 0; i < vCount; ++i) {
			TaintVerification *tv = (TaintVerification *)(vBuf + index);
			index += sizeof(TaintVerification);
			taintVerifications.push_back(tv);
		}
		curVer = taintVerifications.begin();
	}
}

VOID Fini(INT32 code, VOID *v) {
	ExportTaintPolicy();
	procMgr->ReleaseMaps();
}

int main(int argc, char *argv[])
{
	cout<<"[raslr] generating tracking policy "<<endl;
	PIN_InitSymbols();
	if(PIN_Init(argc, argv)){
		string nPrefix = "-nruns=";
		string iPrefix = "-nrun=";
		string nArgv = argv[3];
		string iArgv = argv[4];
		if (nArgv.substr(0, nPrefix.size()) == nPrefix) 
			// number of runs
			nruns = atoi (argv[3] + nPrefix.size());
		else
			return Usage();

		if (iArgv.substr(0, iPrefix.size()) == iPrefix){ 
			// nth run
			nrun = atoi (argv[4] + iPrefix.size());
			if (nrun == 0)
				return Usage();
		}
		else
			return Usage();
	}
	InitAll();
	// taint the return value of syscall-mmap
	PIN_AddSyscallEntryFunction(SyscallEntry, 0);
	PIN_AddSyscallExitFunction(SyscallExit, 0);

	// instrumentation
	IMG_AddInstrumentFunction(ImageLoad, 0);
	INS_AddInstrumentFunction(Instruction, 0);

	PIN_AddFiniFunction(Fini, 0);

	// analysis
	PIN_StartProgram();

	return 0;
}
