/*

	The patching functions will write to memory.
	NOTE: When VirtualProtectEx() is used a PAGE_GUARD gets triggered. If you need more stealth you will have to come up with your own method until I implement one.
	Code by Z0F.

*/
#pragma once
#include <Windows.h>

// Will write to/patch starting at specified mem addr. Can write all R/W/X mem.
// Example: Patch(hProc, (void*)(0x00007FF625631EEA), "\xC7\x44\x24\x40\x0F\x00\x00\x00", 8);
void Patch(HANDLE &hProc, void* dst, char* bytes, const unsigned int &size);

// Will write NOP instructions to a given address. The size parameter is how many NOPs to write.
// Example: Nop(hProc, (void*)(0x00007FF625631EEA), 8);
void Nop(HANDLE &hProc, void* dst, const unsigned int &size);