#ifndef POLICY_REP_H
#define POLiCY_REP_H

#include "raslr.h"
#include <list>

/*
 * Data structures for representing taint policies
 * and taint verifications
 */

// operand types
enum OpeType {
	OpeTypeReg = 1,
	OpeTypeMem = 2,
	OpeTypeImm = 4,
	OpeTypeLea = 8
};

struct InsRep;
struct TaintPolicy;

#ifdef USE_SUB_POLICY
struct SubTaintPolicy;
#endif

// instruction sequence
UINT64 globalInsSeq = 0;

// instruction abstraction
struct InsRep {
	/* static values */
	// opcode
	OPCODE opc;

	// number of operands
	UINT8 opeCount;

	// types of all operands (e.g., reg or mem)
	UINT32 opeTypes;

	// widths of all operands (in bits)
	UINT64 opeWidths;

	// flag indicates if the ope is read
	UINT8 opeRead;

	// flag indicates if the ope is written
	// NOTE, a operand can be both read and written
	UINT8 opeWritten;

	// data of operands, e.g., immediate, reg number
	UINT64 opeData[8];

#ifdef VERBOSE_MODE
	// disassembly
	string dis;
#endif


	/* runtime values */
	// each byte indicates the taintness of each read operand
	// before executing this ins
	// |taintness of read opes|
	UINT64 taintsInR;

	// each byte indicates the taintness of each written operand
	// before executing this ins
	// |taintness of written opes|
	UINT64 taintsInW;

	// each byte indicates the taintness of each written operand
	// after executing this ins
	UINT64 taintsOut;

	// record the written addr before ins is executed
	// the address might be changed after the ins is executed, 
	// e.g., push
	UINT64 toWriteAddr;

	// the highest bits of operands
	UINT8 hiBits[8];

	// name of module containing this ins
	char module[64];

	// offset of this ins in its module
	UINT32 offset;

	// matched taint policy
	TaintPolicy *etp;

	// instruction sequence
	UINT64 insSeq;

	/* member functions */
	// constructing InsRep
	// only static information is abstracted
	InsRep(INS ins) {
		opc = INS_Opcode (ins);
		opeCount = (UINT8)INS_OperandCount(ins);
		raslr_assert(opeCount <= 8, "more than 8 operands");
		opeTypes = 0; 
		opeRead = 0; 
		opeWritten = 0;
		opeWidths = 0;
		UINT8 *width = (UINT8 *)&opeWidths;
		for (UINT32 i = 0; i < opeCount; ++i) {
			opeRead |= ((UINT8)INS_OperandRead(ins, i))<<i;
			opeWritten |= ((UINT8)INS_OperandWritten(ins, i))<<i;
			width[i] = INS_OperandWidth(ins, i);
			if (INS_OperandIsReg(ins, i)) {
				opeTypes |= (OpeTypeReg<<(i * 4));
				// |read flag|reg number|
				opeData[i] = INS_OperandReg(ins, i);
			}
			else if (INS_OperandIsMemory(ins, i)) {
				opeTypes |= (OpeTypeMem<<(i * 4));
				// segment-based address is also supported
			}
			else if (INS_OperandIsImmediate(ins, i)) {
				opeTypes |= (OpeTypeImm<<(i * 4));
				opeData[i] = INS_OperandImmediate(ins, i);
			}
			else if (INS_OperandIsAddressGenerator(ins, i)) {
				opeTypes |= (OpeTypeLea<<(i * 4));
			}
			// implicit operand, e.g., rsp in push ins, is
			// assumed to not change pointer taintness
			else if (INS_OperandIsImplicit(ins, i)) {
			}
			// branch displament, e.g., the ones in direct call/jmp
			// do nothing for this kind of operand
			else if (INS_OperandIsBranchDisplacement(ins, i)) {
			}
			//TODO: segmentation is not supported yet
			else if (INS_OperandIsFixedMemop(ins, i)) {
				raslr_not_reachable();
			}
			else 
				raslr_not_reachable();
		}

		// instruction sequence
		insSeq = globalInsSeq;
		++globalInsSeq;

#ifdef VERBOSE_MODE
		dis = INS_Disassemble(ins); 
#endif
	}
};


/* sub taint policy to eliminate implicit ones */
struct SubTaintPolicy {
#ifdef SUB_POLICY_HIBIT
	// the highest bits of operands
	UINT8 hiBits[8];
#endif

#ifdef SUB_POLICY_LOC
	// name of module, probabaly need more bytes
	char module[64];
	// offset of the instruction into the module base
	UINT32 offset;
#endif

	// each byte indicates if each operand should be tainted 
	// or untainted, given an ins and its operands' state
	UINT64 taintsOut;

	// indicating if the operand should be "always" or 
	// "maybe" tainted/untainted
	UINT64 flags;

	SubTaintPolicy *next;

#ifdef SUB_POLICY_HIBIT
	SubTaintPolicy(UINT8 *hiBits, INT32 count = -1) {
		if (count != -1) {
			memcpy(this->hiBits, hiBits, count);
			memset(this->hiBits + count, 0, 8 - count);
		}
		else
			memcpy(this->hiBits, hiBits, 8);
		flags = 0;
		next = NULL;
	}
#endif

#ifdef SUB_POLICY_LOC
	SubTaintPolicy(char *module, UINT32 offset) {
		strcpy(this->module, module);
		this->offset = offset;
		flags = 0;
		next = NULL;
	}
#endif
};


/* 
 * Taint policy that will be exported
 * It is kind of "shrinked" version
 * of InsRep
 */
struct TaintPolicy {
	// opcode
	OPCODE opc;

	// operands types
	UINT32 opeTypes;

	// widths of all operands
	UINT64 opeWidths;

	// taintness of opes of an ins before it is executed
	UINT64 taintsIn;

	// each byte indicats if each operand should be tainted or 
	// untainted, given this ins and its operands' state
	UINT64 taintsOut;

	// indicating if the operand should be "always" or 
	// "maybe" tainted/untainted
	UINT64 flags;

#ifdef USE_SUB_POLICY
	// sub taint policy list
	SubTaintPolicy *subPolicies;

	// number of sub policies
	UINT32 subPCount;

#ifdef SUB_POLICY_HIBIT
	// the highest bits of operands
	UINT8 hiBits[8];
#endif

#ifdef SUB_POLICY_LOC
	// name of module containing this ins
	char module[64];

	// offset of this ins in its module
	UINT32 offset;
#endif
#endif

#ifdef VERBOSE_MODE
	// disassembly
	char dis[64];
#endif

	// extract opc, opeTypes, and opeWidths
	TaintPolicy() {}

	TaintPolicy(InsRep *rep) {
		opc = rep->opc;
		opeTypes = rep->opeTypes;
		opeWidths = rep->opeWidths;
		taintsIn = rep->taintsInR;
		taintsOut = rep->taintsOut;
		flags = 0;
#ifdef VERBOSE_MODE
		size_t sz = rep->dis.length();
		raslr_assert(sz < 64, "dis > 64 \n");
		rep->dis.copy(dis, sz, 0);
		dis[sz] = '\0';
#endif

#ifdef USE_SUB_POLICY
		subPCount = 0;
#ifdef SUB_POLICY_HIBIT
		// the highest bits of operands
		memcpy(hiBits, rep->hiBits, 8);
#endif

#ifdef SUB_POLICY_LOC
		// name of module containing this ins
		strcpy(module, rep->module);

		// offset of this ins in its module
		offset = rep->offset;
#endif
#endif
	}
};

/* Find existing taint policy */
TaintPolicy *FindPolicy(list<TaintPolicy *> tps, 
		TaintPolicy *tp, BOOL withTaint = true) {
	for (list<TaintPolicy *>::iterator it = tps.begin(); 
			it != tps.end(); ++it) {
		// based on opcode, operands types and tainting state of
		// operands
		if ((*it)->opc == tp->opc && 
				(*it)->opeTypes == tp->opeTypes &&
				(*it)->opeWidths == tp->opeWidths) {
			if (!withTaint || 
					(withTaint && ((*it)->taintsIn == tp->taintsIn)))
				return *it;
		}
	}
	return NULL;
}

TaintPolicy *FindPolicy(list<TaintPolicy *> tps, 
		InsRep *rep, BOOL withTaint = true) {
	for (list<TaintPolicy *>::iterator it = tps.begin(); 
			it != tps.end(); ++it) {
		// based on opcode, operands types and tainting state of
		// operands
		if ((*it)->opc == rep->opc && 
				(*it)->opeTypes == rep->opeTypes &&
				(*it)->opeWidths == rep->opeWidths) {
			if (!withTaint || 
					(withTaint && ((*it)->taintsIn == rep->taintsInR)))
				return *it;
		}
	}
	return NULL;
}

#ifdef SUB_POLICY_HIBIT
SubTaintPolicy *FindSubPolicy(list<SubTaintPolicy *> stps, 
		UINT8 *hiBits, UINT32 opeCount) {
	for (list<SubTaintPolicy *>::iterator it = stps.begin(); 
			it != stps.end(); ++it) {
		if (memcmp((*it)->hiBits, hiBits, opeCount) == 0)
			return *it;
	}
	return NULL;
}


SubTaintPolicy *FindSubPolicy(SubTaintPolicy *stps, 
		UINT8 *hiBits, UINT32 opeCount) {
	while (stps) {
		if (memcmp(stps->hiBits, hiBits, opeCount) == 0)
			return stps;
		stps = stps->next;
	}
	return NULL;
}
#endif

#ifdef SUB_POLICY_LOC
SubTaintPolicy *FindSubPolicy(SubTaintPolicy *stps, 
		SubTaintPolicy *sub) {
	while (stps) {
		if (strcmp(stps->module, sub->module) == 0 && 
				stps->offset == sub->offset)
			return stps;
		stps = stps->next;
	}
	return NULL;
}
#endif

/* verifid taintness with multi-run verification*/
struct TaintVerification {
	// instruction sequence
	UINT64 insSeq;
	// which operands are pointers before execution
	UINT64 taintsIn;
	// which operands are pointers after execution
	UINT64 taintsOut;
};


#endif
