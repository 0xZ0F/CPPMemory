/*
	Functions to write to memory.
	NOTE: When VirtualProtectEx() is used a PAGE_GUARD gets triggered. These functions aren't meant to be sneaky.
	Code by Z0F.
*/
#include "Patching.h"

// Write mem:
void Patch(HANDLE &hProc, void* dst, const char* bytes, const unsigned int &size) {
	DWORD oldProtect;
	VirtualProtectEx(hProc, dst, size, PAGE_EXECUTE_READWRITE, &oldProtect); // PAGE_READWRITE
	WriteProcessMemory(hProc, dst, bytes, size, NULL);
	VirtualProtectEx(hProc, dst, size, oldProtect, &oldProtect);
}

// Write NOPs:
void Nop(HANDLE &hProc, void* dst, const unsigned int &size) {
	byte *nopArray = new byte[size];
	memset(nopArray, 0x90, size);
	DWORD oldProtect;

	VirtualProtectEx(hProc, dst, size, PAGE_EXECUTE_READWRITE, &oldProtect);
	WriteProcessMemory(hProc, dst, nopArray, size, NULL);
	VirtualProtectEx(hProc, dst, size, oldProtect, &oldProtect);
	delete[] nopArray;
}