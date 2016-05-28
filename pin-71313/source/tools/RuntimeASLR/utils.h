
/*
 * some utility routines 
 */

#ifndef UTILS_H
#define UTILS_H

#include "raslr.h"

// context info -- registers
struct Context {
	UINT64 rax;
	UINT64 rbx;
	UINT64 rcx;
	UINT64 rdx;
	UINT64 rsi;
	UINT64 rdi;
	UINT64 rbp;
	UINT64 rsp;
	UINT64 r8;
	UINT64 r9;
	UINT64 r10;
	UINT64 r11;
	UINT64 r12;
	UINT64 r13;
	UINT64 r14;
	UINT64 r15;
	UINT64 rip;
	UINT64 fs;
};


class utils {

	public:

		static VOID PrintIns(string insDis, UINT64 addr);
		static BOOL HasGrRegR(INS ins);
		static BOOL HasGrRegW(INS ins);
		static BOOL HasFrRegR(INS ins);
		static BOOL HasFrRegW(INS ins);
		static BOOL HasPtrWritten(INS ins);
		static BOOL HasImmediate(INS ins);
		static REG GetFullReg(REG reg);  
		static UINT64 Demangle(UINT64 addr, UINT64 key);
		static UINT64 Mangle(UINT64 addr, UINT64 key);

		static UINT32 HiBit(UINT64 value);

		// get timestamp
		static UINT64 rdtsc();

};


/* implementation of member functions */

UINT32 insCount = 0;
VOID utils::PrintIns(string insDis, UINT64 addr) {
	cout<<dec<<insCount<<"("<<hex<<addr<<"). "<<insDis<<endl;
	++insCount;
}

BOOL utils::HasGrRegW(INS ins) {
	for (UINT32 i = 0; i < INS_MaxNumWRegs(ins); ++i) {
		REG regW = INS_RegW(ins, i);
		// rip/eip is also included
		if (REG_is_gr64(regW) || REG_is_gr32(regW) || 
				REG_is_gr16(regW) || //REG_is_gr8(regW) ||
				regW == REG_RIP || regW == REG_EIP) {
			return true;
		}
	}
	return false;
}

BOOL utils::HasGrRegR(INS ins) {
	for (UINT32 i = 0; i < INS_MaxNumRRegs(ins); ++i) {
		REG regR = INS_RegR(ins, i);
		if (REG_is_gr64(regR) || REG_is_gr32(regR) || 
				REG_is_gr16(regR) || REG_is_gr8(regR) ||
				regR == REG_RIP || regR == REG_EIP) {
			return true;
		}
	}
	return false;
}

BOOL utils::HasFrRegW(INS ins) {
	for (UINT32 i = 0; i < INS_MaxNumWRegs(ins); ++i) {
		REG regW = INS_RegW(ins, i);
		if (REG_is_fr(regW)) {
			return true;
		}
	}
	return false;
}

BOOL utils::HasFrRegR(INS ins) {
	for (UINT32 i = 0; i < INS_MaxNumRRegs(ins); ++i) {
		REG regR = INS_RegR(ins, i);
		if (REG_is_fr(regR)) {
			return true;
		}
	}
	return false;
}

BOOL utils::HasPtrWritten(INS ins) {
	for (UINT32 i = 0; i < INS_OperandCount(ins); ++i) {
		if (INS_OperandWritten(ins, i) &&
				INS_OperandWidth(ins, i) >= 32)
			return true;
	}
	return false;
}

BOOL utils::HasImmediate(INS ins) {
	for (UINT32 i = 0; i < INS_OperandCount(ins); ++i) {
		if (INS_OperandIsImmediate(ins, i))
			return true;
	}
	return false;
}

REG utils::GetFullReg(REG reg) {
	switch (reg) {
		case REG_EAX:
		case REG_AX:
		case REG_AH:
		case REG_AL:
			return REG_RAX;
		case REG_EBX:
		case REG_BX:
		case REG_BH:
		case REG_BL:
			return REG_RBX;
		case REG_ECX:
		case REG_CX:
		case REG_CH:
		case REG_CL:
			return REG_RCX;
		case REG_EDX:
		case REG_DX:
		case REG_DH:
		case REG_DL:
			return REG_RDX;
		case REG_EDI:
		case REG_DI:
		case REG_DIL:
			return REG_RDI;
		case REG_ESI:
		case REG_SI:
		case REG_SIL:
			return REG_RSI;
		case REG_EBP:
		case REG_BP:
		case REG_BPL:
			return REG_RBP;
		case REG_ESP:
		case REG_SP:
		case REG_SPL:
			return REG_RSP;
		case REG_R8D:
		case REG_R8W:
		case REG_R8B:
			return REG_R8;
		case REG_R9D:
		case REG_R9W:
		case REG_R9B:
			return REG_R9;
		case REG_R10D:
		case REG_R10W:
		case REG_R10B:
			return REG_R10;
		case REG_R11D:
		case REG_R11W:
		case REG_R11B:
			return REG_R11;
		case REG_R12D:
		case REG_R12W:
		case REG_R12B:
			return REG_R12;
		case REG_R13D:
		case REG_R13W:
		case REG_R13B:
			return REG_R13;
		case REG_R14D:
		case REG_R14W:
		case REG_R14B:
			return REG_R14;
		case REG_R15D:
		case REG_R15W:
		case REG_R15B:
			return REG_R15;
		case REG_EIP:
			return REG_RIP;
		default:
			return reg;
	}
}

UINT64 utils::Demangle(UINT64 addr, UINT64 key) {
	return (addr>>17|addr<<47)^key;
}

UINT64 utils::Mangle(UINT64 addr, UINT64 key) {
	addr ^= key;
	return (addr<<17|addr>>47);
}


UINT32 utils::HiBit(UINT64 value) {
	UINT8 *p = (UINT8 *)&value;
	for (int i = 0; i < 8; ++i) {
		// check each byte
		UINT8 n = p[7 - i];
		if (n) {
			UINT32 ret = 0;
			// check each bit
			while (n) {
				++ret;
				n >>= 1;
			}
			return ret + 8 * (7 - i);
		}
	}
	return 0;
	/*
		 UINT32 n1 = ((UINT32 *)&value)[1];
		 if (n1) {
		 n1 |= (n1 >>  1);
		 n1 |= (n1 >>  2);
		 n1 |= (n1 >>  4);
		 n1 |= (n1 >>  8);
		 n1 |= (n1 >> 16);
		 return (n1 - (n1 >> 1) + 32);
		 }
		 else {
		 UINT32 n0 = ((UINT32 *)&n)[0];
		 n0 |= (n0 >>  1);
		 n0 |= (n0 >>  2);
		 n0 |= (n0 >>  4);
		 n0 |= (n0 >>  8);
		 n0 |= (n0 >> 16);
		 return n1 - (n0 >> 1);
		 }
		 */
}

uint64_t utils::rdtsc(){
	unsigned int lo,hi;
	__asm__ __volatile__ ("rdtsc" : "=a" (lo), "=d" (hi));
	return ((uint64_t)hi << 32) | lo;
}


#endif
