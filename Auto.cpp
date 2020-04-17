///*
//
//	These functions are for QOL. They are pre-built functions for common tasks.
//	Code by Z0F.
//
//*/
#include "Auto.h"

// Size defaults to 0 (set in header file). If size is 0, then the size will automatically be computed.
void AutoWriteToAddress(const std::string& procName, void* dst, char* bytes, const unsigned int &size) {
	DWORD procID = GetProcID(procName);
	HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, false, procID);

	Patch(hProc, dst, bytes, ((size == 0) ? sizeof(bytes) : size));
}

// Size defaults to 0 (set in header file). If size is 0, then the size will automatically be computed.
void AutoWriteToOffset(const std::string& procName, const std::string& modName, const unsigned int &offset, char* bytes, const unsigned int &size) {
	DWORD procID = GetProcID(procName);
	HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, false, procID);

	MODULEENTRY32 modEntry = GetModule(procID, modName);
	if (!modEntry.th32ModuleID) { return; }

	Patch(hProc, (void*)((uintptr_t)modEntry.modBaseAddr + offset), bytes, ((size == 0) ? sizeof(bytes) : size));
}

// Size defaults to 0 (set in header file). If size is 0, then the size will automatically be computed.
void AutoWriteToPattern(const std::string& procName, const std::string& modName, char* pattern, char* mask, char* bytes, const unsigned int &size) {
	DWORD procID = GetProcID(procName);
	HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, false, procID);

	void* patternAddr = PatternScanModule(hProc, procName, modName, pattern, mask);

	if (patternAddr != nullptr) {
		Patch(hProc, patternAddr, bytes, ((size == 0) ? sizeof(bytes) : size));
	}
}