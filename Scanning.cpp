/*

	The pattern scanning functions are used to scan for patterns within a process.
	Question marks in a mask will account for changes in a binary such as hard-coded addresses determined at runtime.
	The core of this code is by Fleep and was modified, commented, and optimized by Z0F.

*/

#include "Scanning.h"
#include <iostream>

// Internal Pattern Scan:
void* PatternScan(char* bytes, size_t size, char* pattern, char* mask) {
	size_t patternLength = strlen(mask);

	// There are two different loops because of how we return.
	// i will loop over the memory, j will loop over the bytes after i to check if those bytes match the pattern. If not, break, i++, repeat.
	for (unsigned int i = 0; i < size - patternLength; i++) {
		bool found = true;
		// For every byte in the chunk of memory, loop through the pattern and check if the bytes match the pattern.
		// If the bytes don't match, the if statement is ran and found is set to false. *(bytes + i + j) is the current byte being compared.
		// If the entire loop runs, then found is true because sequential memory matched the pattern.
		for (unsigned int j = 0; j < patternLength; j++) {
			// If the current mask value is not '?' and the current byte in the pattern is not the current byte being checked in mem, found is false.
			// If the current mask value is a '?' then keep going because that value could be anything ('?' is a wildcard).
			// If the current byte in mem matches the current byte in the pattern, keep going.
			// If both the mask and pattern values match, we've hit an 'x' in the mask and a correct byte in the pattern.
			// Check if j byte in the pattern matches the current byte in the memory being scanned:
			if (mask[j] != '?' && pattern[j] != *(bytes + i + j)) {
				found = false;
				break;
			}
		}
		if (found) {
			// Return only bytes+i not bytes+i+j because we want the start of where the pattern was found. bytes+i+j is the end of the pattern.
			return (void *)(bytes + i);
		}
	}
	return nullptr;
}
// External Wrapper:
void* PatternScanProcess(HANDLE hProc, uintptr_t begin, uintptr_t end, char* pattern, char* mask) {
	uintptr_t currentChunk = begin;
	SIZE_T bytesRead;
	// While the current chunk of 4096 bytes is not at the end, read it and pass that to PatternScan():
	while (currentChunk < end) {
		char buffer[4096];	// Size of chunk we want to read.

		DWORD oldProtect;
		VirtualProtectEx(hProc, (void *)currentChunk, sizeof(buffer), PAGE_EXECUTE_READWRITE, &oldProtect);
		// Read from the current chunk and store it in buffer, also store the num of bytes read in bytesRead:
		ReadProcessMemory(hProc, (void *)currentChunk, &buffer, sizeof(buffer), &bytesRead);
		VirtualProtectEx(hProc, (void *)currentChunk, sizeof(buffer), oldProtect, &oldProtect);

		if (bytesRead == 0) { return nullptr; }

		// Scan the current chunk of memory for the pattern we are looking for using PatternScan():
		void *internalAddress = PatternScan((char *)&buffer, bytesRead, pattern, mask);

		if (internalAddress != nullptr) {
			// Calculate from internal to external:
			// buffer is the internal address of the current chunk, internalAddress is the internal address of the pattern's location.
			uintptr_t offsetFromBuffer = (uintptr_t)internalAddress - (uintptr_t)&buffer;
			// currentChunk is an external addr. Add offsetFromBuffer to get external addr of the pattern's location.
			std::cout << "Found pattern at: " << (void *)(currentChunk + offsetFromBuffer) << std::endl;
			return (void *)(currentChunk + offsetFromBuffer);
		} else {
			// Advance to next chunk:
			currentChunk = currentChunk + bytesRead;
		}
	}
	return nullptr;
}

// Module wrapper for external pattern scan:
void* PatternScanModule(HANDLE hProc, const wchar_t* procName, wchar_t* modName, char* pattern, char* mask) {
	DWORD procID = GetProcID(procName);
	MODULEENTRY32 modEntry = GetModule(procID, modName);

	if (!modEntry.th32ModuleID) {
		return nullptr;
	}

	uintptr_t begin = (uintptr_t)modEntry.modBaseAddr;
	uintptr_t end = begin + modEntry.modBaseSize;
	return PatternScanProcess(hProc, begin, end, pattern, mask);
}