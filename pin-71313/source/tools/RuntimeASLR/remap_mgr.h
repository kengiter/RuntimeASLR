
/*
 * remap_mgr: remapping address space and unmapping pin 
 */

#ifndef REMAP_MGR_H
#define REMAP_MGR_H

#include <sys/types.h>
#include <sys/mman.h>
#include <set>
#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <unistd.h>
#include <asm/prctl.h>
#include <sys/prctl.h>
#include <fcntl.h>
#include "raslr.h"

using namespace std;

#define uint64 unsigned long
#define uint32 unsigned int
#define uint8 unsigned char
#define NUM_PTR_REGS 53

// clear pin's memory after remapping
#define CLEAR_PIN 1

// perform memory analysis for evaluation
// #define MEMORY_ANALYSIS 1

// 28-bit entropy
#define BASE_MASK 0x7ffffffff000


// utils
uint64 Demangle(uint64 addr, uint64 key) {
	return (addr>>17|addr<<47)^key;
}

uint64 Mangle(uint64 addr, uint64 key) {
	addr ^= key;
	return (addr<<17|addr>>47);
}

uint64 rdtsc(){
	uint32 lo,hi;
	__asm__ __volatile__ ("rdtsc" : "=a" (lo), "=d" (hi));
	return ((uint64)hi << 32) | lo;
}

void PrintRegs(uint64 regs[]) {
	cout<<"RAX="<<hex<<regs[0]<<endl;
	cout<<"RBX="<<hex<<regs[1]<<endl;
	cout<<"RCX="<<hex<<regs[2]<<endl;
	cout<<"RDX="<<hex<<regs[3]<<endl;
	cout<<"RSI="<<hex<<regs[4]<<endl;
	cout<<"RDI="<<hex<<regs[5]<<endl;
	cout<<"RBP="<<hex<<regs[6]<<endl;
	cout<<"RSP="<<hex<<regs[7]<<endl;
	cout<<"R8="<<hex<<regs[8]<<endl;
	cout<<"R9="<<hex<<regs[9]<<endl;
	cout<<"R10="<<hex<<regs[10]<<endl;
	cout<<"R11="<<hex<<regs[11]<<endl;
	cout<<"R12="<<hex<<regs[12]<<endl;
	cout<<"R13="<<hex<<regs[13]<<endl;
	cout<<"R14="<<hex<<regs[14]<<endl;
	cout<<"R15="<<hex<<regs[15]<<endl;
	cout<<"RIP="<<hex<<regs[16]<<endl;
	cout<<"FS="<<hex<<regs[17]<<endl;
}

/* structures */

// mapped memory types
enum MapType {
	UnknownMap,
	CodeMap,
	DataMap,
	StackMap,
	HeapMap,
	VdsoMap,
	SharedMap
};

struct mapping {
	uint64 start, end;
	char protS[32];
	uint32 protI;
	uint64 offset;
	uint32 devMajor, devMinor;
	uint64 inode;
	char objFile[128];
	MapType mapType;
	mapping *next;
};

struct remapping {
	mapping *oldMap;
	uint64 moved;
	uint64 reserveSize;
	remapping *baseRemap; // base of a module
	uint64 fixOffset;
	remapping *next;
	remapping() {
		oldMap = NULL;
		moved = 0;
		reserveSize = 0;
		baseRemap = NULL; // base of a module
		fixOffset = 0;
		next = NULL;
	}
};

struct TaintedPtr {
	uint64 addr;
	uint64 base;
	uint8 taint;
	bool operator < (const TaintedPtr &other) const { return addr < other.addr; }
	bool operator > (const TaintedPtr &other) const { return addr > other.addr; }
	bool operator = (const TaintedPtr &other) const { return addr == other.addr; }
};

struct RemapParams {
	uint64 regs[NUM_PTR_REGS];
	mapping *maps;
	mapping *pinMaps;
	remapping *remaps;
	void *(*raslr_mremap)(void *, size_t, size_t, int, void*);
	uint64 mangleKeyAddr;
	set<TaintedPtr>taintedPtrs;
};

class RemapMgr {
	public:
		// operating maps
		mapping *FindMap(uint64 addr);
		mapping *AddMap(uint64 start, uint64 end, uint32 protI);
		mapping *DeleteMap(uint64 start, uint64 end);

		// update pointers in memory
		void UpdateMemRange(uint64 start, uint64 end, 
				uint64 offset);
		// update tracked pointers
		void UpdatePtrsRange(uint64 start, uint64 end,
				uint64 offset);
		// update pointers in registers
		void UpdateRegsRange(uint64 regs[],
				uint64 start, uint64 end, uint64 offset);

		// generate a random base address
		uint64 GetRandBase(uint32 size);
		// remap memory maps
		void RemapMap(remapping *remap);
		void RemapAllMaps(RemapParams *params);

		void MigrateData();
		void ClearPin();

		// transfer control
		void ContextSwitch(uint64 regs[]);

		RemapParams *params;
		mapping *maps;
		remapping *remaps;

		uint64 mangleKey;

		int fRand;
};


/* implementation of member functions */

mapping *RemapMgr::FindMap(uint64 addr) {
	mapping *it = maps;
	while(it) {
		if (it->start <= addr && addr < it->end)
			return it;
		it = it->next;
	}
	return NULL;
}

mapping *RemapMgr::AddMap(uint64 start, uint64 end, uint32 protI) {
	if (end % getpagesize() > 0)
		end = end + (getpagesize() - end % getpagesize());

	mapping *map = new mapping();
	map->start = start; map->end = end;
	map->protI = protI;
	mapping *it = maps;
	while(it) {
		// lowest address
		if (end <= it->start && it == maps) {
			map->next = it;
			maps = map;
			return map;
		}
		// left-aligned 
		else if (start == it->start && end < it->end) {
			mapping *tmpMap = new mapping();
			memcpy(tmpMap, it, sizeof(mapping));
			memcpy(it, map, sizeof(mapping));
			delete map; 
			map = it; it = tmpMap;
			map->next = it;
			it->start = end;
			return map;
		}
		// exact overlap of a mapping
		else if (start == it->start && end == it->end) {
			map->next = it->next;
			memcpy(it, map, sizeof(mapping));
			delete map; map = NULL;
			return it;
		}
		// in the middle of a mapping
		else if (start > it->start && end < it->end) {
			mapping *subMap = new mapping();
			memcpy(subMap, it, sizeof(mapping));
			it->end = start; subMap->start = end;
			map->next = subMap; it->next = map;
			return map;
		}
		// right-aligned
		else if (start > it->start && end == it->end){
			map->next = it->next;
			it->next = map;
			return map;
		}
		// between two mappings
		else if (it->next && it->end <= start 
				&& end <= it->next->start) {
			map->next = it->next;
			it->next = map;
			return map;
		}
		// highest address
		else if (!it->next && start >= it->end) {
			map->next = NULL;
			it->next = map;
			return map;
		}
		it = it->next;
	}
	return NULL;
}

mapping *RemapMgr::DeleteMap(uint64 start, uint64 end) {
	if (end % getpagesize() > 0)
		end = end + (getpagesize() - end % getpagesize());
	mapping *it = maps;
	mapping *prevIt = NULL;
	mapping *deMap = NULL;
	while(it) {
		if (start >= it->start && start < it->end) {
			// in the middle
			if (start > it->start && end < it->end) {
				mapping *subMap = new mapping();
				memcpy(subMap, it, sizeof(mapping));
				it->end = start; subMap->start = end;
				it->next = subMap;

				deMap = new mapping();
				deMap->start = start; 
				deMap->end = end;
				deMap->protI = it->protI;
			}
			// left-aligned
			else if (start == it->start && end < it->end) {
				it->start = end;

				deMap = new mapping();
				deMap->start = start; 
				deMap->end = end;
				deMap->protI = it->protI;
			}
			// right-aligned
			else if (start > it->start && end == it->end) {
				it->end = start;

				deMap = new mapping();
				deMap->start = start; 
				deMap->end = end;
				deMap->protI = it->protI;
			}
			// exact overlap
			else {
				if (prevIt)
					prevIt->next = it->next;
				else
					maps = it->next;
				deMap = it; 
			}
			break;
		}
		prevIt = it;
		it = it->next;
	}
	return deMap;
}

void RemapMgr::UpdateMemRange(uint64 start, uint64 end, 
		uint64 offset) {
	raslr_assert(end >= start, "end < start in update mem range!\n");
	std::set<TaintedPtr>::iterator it = params->taintedPtrs.begin();
	std::set<TaintedPtr>::iterator itTmp;
	while (it != params->taintedPtrs.end()) {
		itTmp = it; 
		++it;
		if (itTmp->addr >= start && itTmp->addr < end) {
			TaintedPtr tp;
			tp.addr = itTmp->addr + offset;
			params->taintedPtrs.erase(itTmp);
			params->taintedPtrs.insert(tp);
		}
	}
}

void RemapMgr::UpdatePtrsRange(uint64 start, uint64 end,
		uint64 offset)
{
	raslr_assert(end >= start, "end < start in update ptr range\n");
	mapping *curMap = NULL;
	bool curProtChanged = false;
	for (std::set<TaintedPtr>::iterator it = 
			params->taintedPtrs.begin(); 
			it != params->taintedPtrs.end(); ++it) {
		uint64 ptr = 0;
		if (it->taint == 2) {
			ptr = Demangle(*(uint64 *)it->addr, mangleKey);
		}
		else 
			ptr = *(uint64 *)(it->addr);
		if (ptr >= start && ptr < end) {
			// make sure it is writable
			if (!curMap || (it->addr < curMap->start || 
						it->addr >= curMap->end)) {
				if (curProtChanged) {
					mprotect((void *)curMap->start, curMap->end - curMap->start, 
							curMap->protI);
					curProtChanged = false;
				}
				curMap = FindMap(it->addr);
				if (!(curMap->protI&PROT_WRITE)) {
					mprotect((void *)curMap->start, curMap->end - curMap->start, 
							(curMap->protI|PROT_WRITE));
					curProtChanged = true;
				}
			}
			// do patching
			if (it->taint == 2)
				ptr = Mangle(ptr + offset, mangleKey);
			else 
				ptr += offset;
			*(uint64 *)(it->addr) = ptr;
		}
	}
}

void RemapMgr::UpdateRegsRange(uint64 regs[],
		uint64 start, uint64 end, uint64 offset) {
	for (uint32 i = 0; i < NUM_PTR_REGS; ++i) {
		if (start <= regs[i] && regs[i] < end)
			regs[i] += offset;
	}
}


/* generate a random and available base address */
uint64 RemapMgr::GetRandBase(uint32 size) {
	// we also do 28 bit entropy as default Linux does
	// so generate a random value like 0x7f???????000,
	// and then check its availability
	uint64 base = 0x7f0000000000;
	while (true) {
		read(fRand, ((uint8 *)&base) + 1, 4);
		base = base&BASE_MASK;
		uint64 tmpBase = (uint64)mmap(
				(caddr_t)base, 
				size, 
				0,
				MAP_ANONYMOUS | MAP_PRIVATE,
				-1, 0);
		if (base == tmpBase) {
			munmap((void *)base, size);
			return base;
		}
	}
}


// do runtime re-randomization
void RemapMgr::RemapMap(remapping *remap) {
	uint64 oldStart = remap->oldMap->start;
	uint64 oldEnd = remap->oldMap->end;
	uint64 size = oldEnd - oldStart;
	uint32 prot = remap->oldMap->protI;
	uint64 newStart = 0;

#ifdef MEMORY_ANALYSIS
	uint64 oldMemory = 0;
	if (remap->oldMap->mapType != SharedMap &&
			prot > 0) {
		oldMemory = (uint64)mmap(
				(caddr_t)0, 
				size, 
				prot|PROT_WRITE|PROT_READ,
				MAP_ANONYMOUS | MAP_PRIVATE,
				-1, 0);
		memcpy((void *)oldMemory, (void *)oldStart, size);
		newStart = oldStart;
	}
	else 
		return;

#else
	if (remap->oldMap->mapType == SharedMap) {
		// TODO: use memcpy to maintain another copy
		// of shared mappings, as they will be still
		// accessed by pin
		return;
	}
	else if (remap->oldMap->mapType == HeapMap) {
		// why the new brk must be lower?
		while (newStart > oldStart || newStart == 0)
			newStart = GetRandBase(size);
		// have to adjust program break
		sbrk(newStart - oldStart);
		newStart = (uint64)params->raslr_mremap((void *)oldStart, 
				size,
				size,
				MREMAP_MAYMOVE|MREMAP_FIXED, 
				(void *)newStart);
	}
	else {
		uint64 vSize = remap->reserveSize > 0 ? 
			remap->reserveSize : size;
		if (remap->fixOffset) {
			newStart = remap->baseRemap->oldMap->start +
				remap->baseRemap->moved + remap->fixOffset;
		}
		else {
			// generate a random and available base
			newStart = GetRandBase(vSize);
		}
		// remapping
		newStart = (uint64)params->raslr_mremap((void *)oldStart, 
				size,
				size,
				MREMAP_MAYMOVE|MREMAP_FIXED, 
				(void *)newStart);
	}
#endif

	remap->moved = newStart - oldStart;
	// updating maps
#ifdef MEMORY_ANALYSIS
#else
	AddMap(newStart, newStart + size, prot);
	DeleteMap(oldStart, oldEnd);
#endif
	// updating taintness
	UpdateMemRange(oldStart, oldEnd, 
			newStart - oldStart);
	if (params->mangleKeyAddr >= oldStart && 
			params->mangleKeyAddr < oldEnd)
		params->mangleKeyAddr += (newStart - oldStart);
	mangleKey = *(uint64 *)params->mangleKeyAddr;
	UpdatePtrsRange(oldStart, oldEnd, newStart - oldStart);
	UpdateRegsRange(params->regs, oldStart, oldEnd, 
			newStart - oldStart);

#ifdef MEMORY_ANALYSIS
	mprotect((void *)oldStart, size, prot|PROT_READ); 
	if (memcmp((void *)oldMemory, (void *)oldStart, size) != 0) {
		cout<<"[raslr] "<<hex<<oldStart<<", "<<
			oldEnd<<" is NOT consistent! "<<
			remap->oldMap->objFile<<endl;
	}
	else
		cout<<"[raslr] "<<hex<<oldStart<<", "<<
			oldEnd<<" is consistent! "<<
			remap->oldMap->objFile<<endl;
	mprotect((void *)oldStart, size, prot); 
#endif

	cout<<"[raslr] remapped <"<<hex<<oldStart<<", "<<
		oldEnd<<"> to <"<<newStart<<", "<<newStart + size<<
		">"<<endl;
}

void RemapMgr::RemapAllMaps(RemapParams *params) {
#ifdef MICRO_BENCH
	cout<<"[cycle] Enter remapping: "<<dec<<rdtsc()<<endl;
#endif
	this->params = params;
	this->maps = params->maps;
	this->remaps = params->remaps;
	remapping *remap = remaps;
	fRand = open("/dev/urandom", 0);
	while (remap) {
		RemapMap(remap);
		remap = remap->next;
	}
	close(fRand);

#ifdef MICRO_BENCH
	cout<<"[cycle] Exit remapping: "<<dec<<rdtsc()<<endl;
#endif
	// prepare the context and control transfer
	ContextSwitch(params->regs);
}

void RemapMgr::MigrateData() {
	mapping *it = params->pinMaps;
	mapping *curNewIt = NULL;
	while (it) {
		mapping *newIt = new mapping();
		memcpy((void *)newIt, (void *)it, sizeof(mapping));
		if (curNewIt == NULL) 
			params->pinMaps = newIt;
		else
			curNewIt->next = newIt;
		curNewIt = newIt;

		it = it->next;
		// no need to release :)
	}
}


void RemapMgr::ContextSwitch(uint64 regs[]) {
	// update fs segment register
	UINT64 fs = regs[48];
	asm volatile (
			"mov %0, %%rsi \n\t"
			"mov $0x1002, %%rdi \n\t"
			"mov $0x9e, %%eax \n\t"
			"syscall \n\t"
			:
			:"r"(fs)
			);
	//prctl(ARCH_SET_GS, regs[49]);


	// update general registers
	// NOTE: xmm operation must be 16-bytes aligned
	uint64 rsp = regs[7] - 
		NUM_PTR_REGS * sizeof(uint64) - 0x108;
	memcpy((void *)rsp, (void *)regs,
			NUM_PTR_REGS * sizeof(uint64));

#ifdef CLEAR_PIN
	/* clean up pin maps */
	uint64 pinHeapBase = 0;
	uint64 pinHeapEnd = 0;
	uint64 pinStackBase = 0;
	uint64 pinStackEnd = 0;
	mapping *pinMap = params->pinMaps;
	uint64 libcBase = 0;
	// do NOT call any library function from now on!
	while (pinMap) {
		// they've alreadly been remapped, do not unmap them
		if (pinMap->mapType == SharedMap) {
			pinMap = pinMap->next;
			continue;
		}
		// special cares taken for pin heap and stack
		// address range of pin heap
		if (pinMap->start <= (uint64)pinMap && 
				(uint64)pinMap < pinMap->end) {
			pinHeapBase = pinMap->start;
			pinHeapEnd = pinMap->end;
			pinMap = pinMap->next;
			continue;
		}
		// address range of pin stack
		else if (pinMap->start <= (uint64)&pinStackBase && 
				(uint64)&pinStackBase < pinMap->end) {
			pinStackBase = pinMap->start;
			pinStackEnd = pinMap->end;
			pinMap = pinMap->next;
			continue;
		}

		asm volatile (
				"push %%rdi \n\t"
				"push %%rsi \n\t"
				"push %%rax \n\t"
				"mov %0, %%rdi \n\t"
				"mov %1, %%rsi \n\t"
				"mov $11, %%eax \n\t"
				"syscall \n\t"
				"pop %%rax \n\t"
				"pop %%rsi \n\t"
				"pop %%rdi \n\t"
				:
				:"r"(pinMap->start), "r"(pinMap->end - pinMap->start)
				);
		pinMap = pinMap->next;
	}


	// now we are safe to unmap heap
	asm volatile (
			"mov %0, %%rdi \n\t"
			"mov %1, %%rsi \n\t"
			"mov $11, %%eax \n\t"
			"syscall \n\t"
			:
			:"r"(pinHeapBase), "r"(pinHeapEnd - pinHeapBase)
			);
	// instead of unmap pin stack, we clear its data
	// keep current stack frame, otherwise, it crashes
	for (uint64 *i = (uint64 *)&pinStackBase + 0x60; 
			i < (uint64 *)(pinStackEnd); ++i) {
		*i = 0;
	}

#endif


	/* context switch and control transfer */
	asm volatile (
			// prepare rsp
			"mov %0, %%rsp \n\t"
			// load general registers
			"pop %%rax \n\t"
			"pop %%rbx \n\t"
			"pop %%rcx \n\t"
			"pop %%rdx \n\t"
			"pop %%rsi \n\t"
			"pop %%rdi \n\t"
			"pop %%rbp \n\t"
			"pop %%r8 \n\t"
			"pop %%r8 \n\t"
			"pop %%r9 \n\t"
			"pop %%r10 \n\t"
			"pop %%r11 \n\t"
			"pop %%r12 \n\t"
			"pop %%r13 \n\t"
			"pop %%r14 \n\t"
			"pop %%r15 \n\t"
			// load float registers
			"movdqa (%%rsp), %%xmm0 \n\t"
			"add $0x10, %%rsp \n\t"
			"movdqa (%%rsp), %%xmm1 \n\t"
			"add $0x10, %%rsp \n\t"
			"movdqa (%%rsp), %%xmm2 \n\t"
			"add $0x10, %%rsp \n\t"
			"movdqa (%%rsp), %%xmm3 \n\t"
			"add $0x10, %%rsp \n\t"
			"movdqa (%%rsp), %%xmm4 \n\t"
			"add $0x10, %%rsp \n\t"
			"movdqa (%%rsp), %%xmm5 \n\t"
			"add $0x10, %%rsp \n\t"
			"movdqa (%%rsp), %%xmm6 \n\t"
			"add $0x10, %%rsp \n\t"
			"movdqa (%%rsp), %%xmm7 \n\t"
			"add $0x10, %%rsp \n\t"
			"movdqa (%%rsp), %%xmm8 \n\t"
			"add $0x10, %%rsp \n\t"
			"movdqa (%%rsp), %%xmm9 \n\t"
			"add $0x10, %%rsp \n\t"
			"movdqa (%%rsp), %%xmm10 \n\t"
			"add $0x10, %%rsp \n\t"
			"movdqa (%%rsp), %%xmm11 \n\t"
			"add $0x10, %%rsp \n\t"
			"movdqa (%%rsp), %%xmm12 \n\t"
			"add $0x10, %%rsp \n\t"
			"movdqa (%%rsp), %%xmm13 \n\t"
			"add $0x10, %%rsp \n\t"
			"movdqa (%%rsp), %%xmm14 \n\t"
			"add $0x10, %%rsp \n\t"
			"movdqa (%%rsp), %%xmm15 \n\t"
			"add $0x10, %%rsp \n\t"
			// skip seg regs
			"add $0x10, %%rsp \n\t"
			// set rflags?
			"add $0x8, %%rsp \n\t"
			// set mxcsr
			"ldmxcsr (%%rsp) \n\t"
			"add $0x8, %%rsp \n\t"
			// set rip
			"add $0x110, %%rsp \n\t"
			"jmp *-0x110(%%rsp) \n\t"
			//"ret \n\t"
			:
			:"r"(rsp)
			);
}


#endif
