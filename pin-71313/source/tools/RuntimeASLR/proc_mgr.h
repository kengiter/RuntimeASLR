
/*
 * process manager: managing mapping, heap object, etc 
 */

#ifndef PROC_MGR_H
#define PROC_MGR_H

#include <sys/types.h>
#include <sys/mman.h>
#include <set>
#include "raslr.h"
#include "utils.h"

// mapping types
enum MapType {
	UnknownMap,
	CodeMap,
	DataMap,
	StackMap,
	HeapMap,
	VdsoMap,
	SharedMap // mapping shared with pin
};

struct mapping {
	UINT64 start, end;
	char protS[32];
	UINT32 protI;
	UINT64 offset;
	UINT32 devMajor, devMinor;
	UINT64 inode;
	char objFile[128];
	MapType mapType;
	mapping *next;
};

struct remapping {
	mapping *oldMap;
	mapping *newMap;
	UINT64 reserveSize;
	remapping *baseRemap;
	UINT64 fixOffset;
	remapping *next;
	remapping() {
		oldMap = NULL;
		newMap = NULL;
		reserveSize = 0;
		baseRemap = NULL; // base of a module
		fixOffset = 0;
		next = NULL;
	}
};

struct HeapObj {
	UINT64 addr;
	UINT64 size;
	bool operator < (const HeapObj &other) const { return addr < other.addr; }
	bool operator > (const HeapObj &other) const { return addr > other.addr; }
	bool operator = (const HeapObj &other) const { return addr == other.addr; }
};

struct FileObj {
	INT32 fd;
	char fn[PATH_MAX];
	bool operator < (const FileObj &other) const { return fd < other.fd; }
	bool operator > (const FileObj &other) const { return fd > other.fd; }
	bool operator = (const FileObj &other) const { return fd == other.fd; }
};

class ProcMgr {
	public:
		ProcMgr(pid_t pid) { 
			this->pid = pid; 
			remaps = NULL;
			maps = NULL;
			pinMaps = NULL;
		};
		VOID LoadMaps();
		VOID LoadInitMaps(CONTEXT *ctx);
		mapping *LoadOneMap(UINT64 start, UINT64 end);
		VOID ReleaseMaps();
		mapping *FindMap(UINT64 addr);
		remapping *FindRemap(UINT64 addr);

		mapping *AddMap(UINT64 start, UINT64 end, UINT32 protI, 
				MapType mapType = UnknownMap,
				const char *file = "");
		mapping *DeleteMap(UINT64 start, UINT64 end);
		remapping *AddRemap(mapping *oldMap, mapping *newMap);

		VOID PrintAppMaps();
		VOID PrintAllMaps();
		VOID PrintPinMaps();

		// check if the given address points to any loaded module
		BOOL IsValidAddress(UINT64 addr);
		BOOL IsMangledAddress(UINT64 addr, CONTEXT *ctx);
		BOOL IsHeapObjAddress(UINT64 addr);
		INT32 GetProtOfAddress(UINT64 addr);

		char *GetFileName(INT32 fd);

		// mapping list 
		pid_t pid;
		mapping *maps;
		mapping *pinMaps;
		remapping *remaps;

		set<HeapObj>heapObjs;
		set<FileObj>fileObjs;
};

VOID ProcMgr::PrintAppMaps() {
	mapping *map = maps;
	while(map) {
		printf("%lx-%lx %31s(%x) %8lx %x:%x %lu %s\n", map->start, 
				map->end, map->protS, map->protI, map->offset, 
				map->devMajor, map->devMinor, map->inode, map->objFile);
		map = map->next;
	}
}

VOID ProcMgr::PrintPinMaps() {
	mapping *map = pinMaps;
	while(map) {
		printf("%lx-%lx %31s(%x) %8lx %x:%x %lu %s\n", map->start, 
				map->end, map->protS, map->protI, map->offset, 
				map->devMajor, map->devMinor, map->inode, map->objFile);
		map = map->next;
	}
}

VOID ProcMgr::PrintAllMaps() {
	char fileName[32];
	sprintf(fileName, "/proc/%d/maps", pid);
	if(!freopen(fileName, "r", stdin)) return;
	char mapBuf[256];
	while(fgets(mapBuf, sizeof(mapBuf), stdin))
		printf("%s", mapBuf);
	fclose(stdin);
}

VOID ProcMgr::LoadMaps() {
	char fileName[32];
	sprintf(fileName, "/proc/%d/maps", pid);
	if(!freopen(fileName, "r", stdin)) return;
	mapping *cur = NULL;
	char mapBuf[256];
	BOOL isHead = true;
	while(fgets(mapBuf, sizeof(mapBuf), stdin)){
		char *tmp = strchr(mapBuf,'\n');
		if(tmp) *tmp='\0';
		mapping *map = new mapping();
		sscanf(mapBuf,"%lx-%lx %31s %lx %x:%x %lu %s", &(map->start), 
				&(map->end), map->protS, &(map->offset), &(map->devMajor),
				&(map->devMinor), &(map->inode), map->objFile);
		map->next = NULL;
		if (isHead) {
			maps = map;
			isHead = false;
		}
		else
			cur->next = map;
		cur = map;
	}
	fclose(stdin);
}

VOID ProcMgr::LoadInitMaps(CONTEXT *ctx) {
	UINT64 ldBase = 0, /*ldEnd = 0,*/ appBase = 0, appEnd = 0;
	string appName;
	for (IMG img= APP_ImgHead(); IMG_Valid(img); img = IMG_Next(img)) {
		if (IMG_IsMainExecutable(img)) {
			appBase = IMG_LowAddress(img);
			appEnd = IMG_HighAddress(img);
			appName = IMG_Name(img);
		}
		else {
			ldBase = IMG_LowAddress(img);
			//ldEnd = IMG_HighAddress(img);
		}
	}
	UINT64 rsp = PIN_GetContextReg(ctx, REG_RSP);

	char fileName[32];
	sprintf(fileName, "/proc/%d/maps", pid);
	if(!freopen(fileName, "r", stdin)) return;
	mapping *curApp = NULL;
	mapping *curPin = NULL;
	char mapBuf[256];
	UINT32 randAddrCount = 0;
	while(fgets(mapBuf, sizeof(mapBuf), stdin)){
		char *tmp = strchr(mapBuf,'\n');
		if(tmp) *tmp='\0';
		mapping *map = new mapping();
		sscanf(mapBuf,"%lx-%lx %31s %lx %x:%x %lu %s", &(map->start), 
				&(map->end), map->protS, &(map->offset), &(map->devMajor),
				&(map->devMinor), &(map->inode), map->objFile);
		if (map->start > MAX_ADDRESS)
			continue;
		// FIXME: a weird mapping that must be included as app maps
		if (map->start > 0x7f0000000000)
			++randAddrCount;
		map->next = NULL;
		if (strchr(map->protS, 'x'))
			map->protI |= PROT_EXEC;
		if (strchr(map->protS, 'r'))
			map->protI |= PROT_READ;
		if (strchr(map->protS, 'w'))
			map->protI |= PROT_WRITE;

		BOOL isAppMap = false;
		BOOL isPinMap = false;
		// mappings of both app and pin
		if (
				// executable and writable memory is potentially shared
				(map->protI&PROT_EXEC && 
				 map->protI&PROT_WRITE &&
				 map->start > 0x7f0000000000 &&
				 !strstr(map->objFile, "stack"))
			 ) {
			isAppMap = true;
			isPinMap = true;
			map->mapType = SharedMap;
		}
		// mappings of app
		else if ((map->start == appBase || 
					appName.compare(map->objFile) == 0 ||
					(map->start < appEnd && map->end >= appEnd)) ||
				// stack
				(map->start < rsp && map->end > rsp) ||
				// vdso
				(strstr(map->objFile, "[vdso]")) ||
				// vvar
				(strstr(map->objFile, "[vvar]")) ||
				// mappings of loader
				// FIXME: this implementation is ad hoc
				// need to find a better way
				(map->start == ldBase || // code sec
				 map->start == ldBase + 0x222000 ||
				 map->start == ldBase + 0x224000) 
				) { 
			isAppMap = true;

		}
		// mappings of pin
		else {
			isPinMap = true;
		}

		// appending the map
		if (isAppMap) {
			if (!maps) {
				maps = map;
			}
			else
				curApp->next = map;
			curApp = map;
		}
		if (isPinMap) {
			if (isAppMap) {
				// duplicate the map
				mapping *mapTmp = new mapping();
				memcpy((VOID *)mapTmp, (VOID *)map, sizeof(mapping));
				map = mapTmp;
			}
			if (!pinMaps)
				pinMaps = map;
			else
				curPin->next = map;
			curPin = map;
		}
	}
#ifdef VERBOSE_MODE
	PrintAppMaps();
#endif
	fclose(stdin);
}
mapping *ProcMgr::LoadOneMap(UINT64 start, UINT64 end) {
	char fileName[32];
	sprintf(fileName, "/proc/%d/maps", pid);
	if(!freopen(fileName, "r", stdin)) return NULL;
	char mapBuf[256];
	while(fgets(mapBuf, sizeof(mapBuf), stdin)){
		char *tmp = strchr(mapBuf,'\n');
		if(tmp) *tmp='\0';
		mapping *map = new mapping();
		sscanf(mapBuf,"%lx-%lx %31s %lx %x:%x %lu %s", &(map->start), 
				&(map->end), map->protS, &(map->offset), &(map->devMajor),
				&(map->devMinor), &(map->inode), map->objFile);
		if (map->start == start && map->end == end) {
			map->next = NULL;
			fclose(stdin);
			return map;
		}
	}
	fclose(stdin);
	return NULL;
}

VOID ProcMgr::ReleaseMaps() {
	mapping *iter = maps;
	while(iter) {
		mapping *cur = iter;
		iter = iter->next;
		delete(cur);
		cur = NULL;
	}
}

mapping *ProcMgr::AddMap(UINT64 start, UINT64 end, UINT32 protI,
		MapType mapType, const char *file) {
	raslr_assert((start % getpagesize()) == 0, 
			"Mapped address is not page size aligned\n");
#ifdef VERBOSE_MODE
	cout<<"adding map: "<<hex<<start<<" "<<end<<endl;
#endif
	if (end % getpagesize() > 0)
		end = end + (getpagesize() - end % getpagesize());

	mapping *map = new mapping();//LoadOneMap(start, end);
	raslr_assert(map, "Cannot load map\n"); 
	map->start = start; 
	map->end = end;
	map->protI = protI;
	map->mapType = mapType;
	strcpy(map->objFile, file);
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
			map = it; 
			it = tmpMap;
			map->next = it;
			it->start = end;
			return map;
		}
		// exact overlap of a mapping
		else if (start == it->start && end == it->end) {
			map->next = it->next;
			memcpy(it, map, sizeof(mapping));
			delete map; 
			map = NULL;
			return it;
		}
		// in the middle of a mapping
		else if (start > it->start && end < it->end) {
			mapping *subMap = new mapping();
			memcpy(subMap, it, sizeof(mapping));
			it->end = start; 
			subMap->start = end;
			map->next = subMap; 
			it->next = map;
			return map;
		}
		// right-aligned
		else if (start > it->start && end == it->end){
			map->next = it->next;
			it->next = map;
			return map;
		}
		// case of brk
		else if (start == it->start && end > it->end) {
			it->end = end;
			delete map;
			map = NULL;
			return it;
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
	raslr_assert(it, "Unrecognized mapping\n");
	return NULL;
}

mapping *ProcMgr::DeleteMap(UINT64 start, UINT64 end) {
	raslr_assert((start % getpagesize()) == 0, 
			"Mapped address is not page size aligned\n");
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
				deMap->mapType = it->mapType;
			}
			// left-aligned
			else if (start == it->start && end < it->end) {
				it->start = end;

				deMap = new mapping();
				deMap->start = start; 
				deMap->end = end;
				deMap->protI = it->protI;
				deMap->mapType = it->mapType;
			}
			// right-aligned
			else if (start > it->start && end == it->end) {
				it->end = start;

				deMap = new mapping();
				deMap->start = start; 
				deMap->end = end;
				deMap->protI = it->protI;
				deMap->mapType = it->mapType;
			}
			// exact overlap
			else if (start == it->start && end == it->end){
				if (prevIt)
					prevIt->next = it->next;
				else
					maps = it->next;
				deMap = it; 
			}
			// cross maps--delete multiple maps
			else if (end > it->end) {
				mapping *endMap = FindMap(end - 1);
				raslr_assert(endMap != NULL, "Can not find map!\n");
				prevIt->next = endMap->next;
				while (it != endMap->next) {
					mapping *tmp = it;
					it = it->next;
					delete tmp;
				}
			}
			break;
		}
		prevIt = it;
		it = it->next;
	}
	return deMap;
}

remapping *ProcMgr::AddRemap(mapping *oldMap, mapping *newMap) {
	remapping *remap = new remapping();
	remap->oldMap = oldMap;
	remap->newMap = newMap;
	remap->next = NULL;

	// add it to remaps list
	if (remaps == NULL)
		remaps = remap;
	else {
		remapping *it = remaps;
		while (it) {
			if (it->next)
				it = it->next;
			else {
				it->next = remap;
				break;
			}
		}
	}
	return remap;
}

mapping *ProcMgr::FindMap(UINT64 addr) {
	mapping *it = maps;
	while(it) {
		if (it->start <= addr && addr < it->end)
			return it;
		it = it->next;
	}
	return NULL;
}

remapping *ProcMgr::FindRemap(UINT64 addr) {
	remapping *it = remaps;
	while(it) {
		if (it->oldMap->start <= addr && addr < it->oldMap->end)
			return it;
		it = it->next;
	}
	return NULL;
}


// check if the given address points to any loaded module
BOOL ProcMgr::IsValidAddress(UINT64 addr) {
	if (addr < MIN_ADDRESS || addr > MAX_ADDRESS)
		return false;
	mapping *it = maps;
	while(it) {
		if (addr >= it->start && addr <= it->end)
			return true;
		it = it->next;
	}
	return false;
}

// check if the given address is a mangled address
BOOL ProcMgr::IsMangledAddress(UINT64 addr, CONTEXT *ctx) {
	UINT64 keyAddr = 
		PIN_GetContextReg(ctx, REG_SEG_FS_BASE) + 0x30;
	if (!(IsValidAddress(keyAddr)))
		return false;
	UINT64 key = *(UINT64 *)keyAddr;
	if (!key)
		return false;
	return IsValidAddress(utils::Demangle(addr, key));
}

BOOL ProcMgr::IsHeapObjAddress(UINT64 addr) {
	if (addr < MIN_ADDRESS || addr > MAX_ADDRESS)
		return false;
	for (set<HeapObj>::iterator it=heapObjs.begin(); 
			it!=heapObjs.end(); ++it) {
		if (addr >= it->addr && addr < it->addr + it->size)
			return true;
	}
	return false;
}

// check if the given address is in writable memory
INT32 ProcMgr::GetProtOfAddress(UINT64 addr) {
	mapping *it = maps;
	while(it) {
		if (addr >= it->start && addr <= it->end)
			return it->protI;
		it = it->next;
	}
	return PROT_NONE;
}

char *ProcMgr::GetFileName(INT32 fd) {
	for (set<FileObj>::iterator it=fileObjs.begin(); 
			it!=fileObjs.end(); ++it) {
		if (fd == it->fd)
			return (char *)(it->fn);
	}
	return (char *)"";
}


#endif
