/*

	The patching functions will write to memory.
	NOTE: When VirtualProtectEx() is used a PAGE_GUARD gets triggered. If you need more stealth you will have to come up with your own method until I implement one.
	Code by Z0F.

*/

#include <iostream>
#include "Patching.h"

// Will write to/patch starting at specified address. Can write to data and code sections (all R/W/X memory) thanks to VirtualProtectEx().
// Example: Patch(hProc, (void*)(0x00007FF625631EEA), "\xC7\x44\x24\x40\x0F\x00\x00\x00", 8);
void Patch(HANDLE &hProc, void* dst, char* bytes, const unsigned int &size) {
	std::cout << "Patching At: " << dst << std::endl;

	// Change memory protection to allow for writing, write, then restore to previous protection level:
	DWORD oldProtect;
	VirtualProtectEx(hProc, dst, size, PAGE_EXECUTE_READWRITE, &oldProtect);
	WriteProcessMemory(hProc, dst, bytes, size, NULL);
	VirtualProtectEx(hProc, dst, size, oldProtect, &oldProtect);
}

// Will write NOP instructions to a given address. The size parameter is how many NOPs to write.
// Example: Nop(hProc, (void*)(0x00007FF625631EEA), 8);
void Nop(HANDLE &hProc, void* dst, const unsigned int &size) {
	std::cout << "Nop At: " << dst << std::endl;

	// NOP array to write into memory:
	byte *nopArray = new byte[size];
	memset(nopArray, 0x90, size);
	DWORD oldProtect;

	// Change memory protection to allow for writing, write, then restore to previous protection level:
	VirtualProtectEx(hProc, dst, size, PAGE_EXECUTE_READWRITE, &oldProtect);
	WriteProcessMemory(hProc, dst, nopArray, size, NULL);
	VirtualProtectEx(hProc, dst, size, oldProtect, &oldProtect);
	delete[] nopArray;
}

// Internal patch:
/*void Patch(void* dst, void* src, unsigned int size) {
	std::cout << "Patch At: " << dst << std::endl;

	DWORD oldProtect;
	VirtualProtect(dst, size, PAGE_EXECUTE_READWRITE, &oldProtect);
	memcpy(dst, src, size);
	VirtualProtect(dst, size, oldProtect, &oldProtect);
}*/

//Internal Nop
/*void Nop(void* dst, unsigned int size) {
	std::cout << "Nop At: " << dst << std::endl;

	DWORD oldProtect;
	VirtualProtect(dst, size, PAGE_EXECUTE_READWRITE, &oldProtect);
	memset(dst, 0x90, size);
	VirtualProtect(dst, size, oldProtect, &oldProtect);
}*/