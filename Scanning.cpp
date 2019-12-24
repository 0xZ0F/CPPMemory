#include "Scanning.h"
#include <iostream>

// Internal Pattern Scan:
void* PatternScan(char* base, size_t size, char* pattern, char* mask) {
	size_t patternLength = strlen(mask);

	// Size = amount of mem being read (Ex. 4096).
	// Loop over every byte in memory and compare it to the mask and pattern.
	// There are two different loops because of how we return.
	// i will loop over the memory, j will loop over the bytes after i to check if those bytes match the pattern. If not, break, i++, repeat.
	for (unsigned int i = 0; i < size - patternLength; i++) {
		bool found = true; // Default to true.
		// For every byte in the memory region we're scanning, loop through the pattern and check if the bytes in mem match the pattern.
		// If the bytes don't match, the if statement is ran and found is set to false.*(base + i + j) is the current bytes being compared in mem.
		// If the entire loop runs, then found is true because sequential memory matched the pattern.
		for (unsigned int j = 0; j < patternLength; j++) {
			// If the current mask value is not '?' and the current byte in the pattern does not the current byte being checked in mem, found is false.
			// If the current mask value is a '?' then keep going because that value could be anything.
			// If the current byte in mem matches the current byte in the pattern, keep going.
			// If both the mask and pattern values match, we've hit an 'x' in the mask and a correct byte in the pattern.
			// Check if j byte in the pattern matches the current byte in mem
			if (mask[j] != '?' && pattern[j] != *(base + i + j)) {
				found = false;
				break;
			}
		}
		if (found) {
			// Return only base+i not base+i+j because we want the start of where the pattern was found.
			return (void*)(base + i);
		}
	}
	return nullptr;
}
// External Wrapper:
void* PatternScanEx(HANDLE hProc, uintptr_t begin, uintptr_t end, char* pattern, char* mask) {
	uintptr_t currentChunk = begin;
	SIZE_T bytesRead;
	// While the current chunk of 4096 bytes is not at the end, read it and pass that to PatternScan():
	while (currentChunk < end) { //0x5000 - 0x6000
		char buffer[4096];	// Size of chunk we want to read from, 4096 is one page.

		DWORD oldProtect;
		VirtualProtectEx(hProc, (void*)currentChunk, sizeof(buffer), PAGE_EXECUTE_READWRITE, &oldProtect);
		// Read from the current chunk and store it in buffer, also store the num of bytes read in bytesRead.
		ReadProcessMemory(hProc, (void*)currentChunk, &buffer, sizeof(buffer), &bytesRead);
		VirtualProtectEx(hProc, (void*)currentChunk, sizeof(buffer), oldProtect, &oldProtect);

		if (bytesRead == 0) { return nullptr; }

		// Scan the current region in mem for the pattern we are looking for:
		// base = &buffer, size = bytesRead, pattern = pattern, mask = mask.
		void* internalAddress = PatternScan((char*)&buffer, bytesRead, pattern, mask);

		if (internalAddress != nullptr) {
			// Calculate from internal to external:
			// buffer is the address of the internal addr of the current chunk, internalAddress is the internal addr of the pattern's location.
			uintptr_t offsetFromBuffer = (uintptr_t)internalAddress - (uintptr_t)&buffer;
			// currentChunk is an external addr. Add offsetFromBuffer to get external addr of the pattern's location.
			std::cout << "Found pattern at: " << (void*)(currentChunk + offsetFromBuffer) << std::endl;
			return (void*)(currentChunk + offsetFromBuffer);
		} else {
			// Advance to next chunk:
			currentChunk = currentChunk + bytesRead;
		}
	}
	return nullptr;
}

// Module wrapper for external pattern scan:
void* PatternScanExModule(HANDLE hProc, wchar_t* exeName, wchar_t* module, char* pattern, char* mask) {
	DWORD procID = GetProcID(exeName);
	MODULEENTRY32 modEntry = GetModule(procID, module);

	if (!modEntry.th32ModuleID) {
		return nullptr;
	}

	uintptr_t begin = (uintptr_t)modEntry.modBaseAddr;
	uintptr_t end = begin + modEntry.modBaseSize;
	return PatternScanEx(hProc, begin, end, pattern, mask);
}