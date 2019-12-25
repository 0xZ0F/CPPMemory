/*

	These functions are for QOL. They are pre-built functions for common tasks.
	Code by Z0F.

*/

#include "Auto.h"

// Size defaults to 0. If size is 0, then the size will automatically be computed.
void AutoWriteToAddress(const wchar_t* procName, void* dst, char* bytes, const unsigned int &size = 0) {
	DWORD procID = GetProcID(procName);
	HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, false, procID);

	PatchEx(hProc, dst, bytes, ((size == 0) ? sizeof(bytes) : size));
}

// Size defaults to 0. If size is 0, then the size will automatically be computed.
void AutoWriteToOffset(const wchar_t* procName, wchar_t* modName, const unsigned int &offset, char* bytes, const unsigned int &size = 0) {
	DWORD procID = GetProcID(procName);
	HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, false, procID);

	MODULEENTRY32 modEntry = GetModule(procID, modName);
	if (!modEntry.th32ModuleID) { return; }

	PatchEx(hProc, (void*)((uintptr_t)modEntry.modBaseAddr + offset), bytes, ((size == 0) ? sizeof(bytes) : size));
}

// Size defaults to 0. If size is 0, then the size will automatically be computed.
void AutoWriteToPattern(const wchar_t* procName, wchar_t* modName, char* pattern, char* mask, char* bytes, const unsigned int &size = 0) {
	DWORD procID = GetProcID(procName);
	HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, false, procID);

	void* patternAddr = PatternScanExModule(hProc, procName, modName, pattern, mask);

	if (patternAddr != nullptr) {
		PatchEx(hProc, patternAddr, bytes, ((size == 0) ? sizeof(bytes) : size));
	}
}