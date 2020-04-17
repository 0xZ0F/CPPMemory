/*
	The pattern scanning functions are used to scan for patterns within a process.
	Question marks in a mask will account for changes in a binary such as addresses determined at runtime.
	The core of this code is by Fleep; Modified and optimized by Z0F.
*/

#include "Scanning.h"

// Actual pattern scanning:
void* PatternScan(char* bytes, size_t size, char* pattern, char* mask) {
	size_t patternLength = strlen(mask);
	for (unsigned int i = 0; i < size - patternLength; i++) {
		bool found = true;
		for (unsigned int j = 0; j < patternLength; j++) {
			if (mask[j] != '?' && pattern[j] != *(bytes + i + j)) {
				found = false;
				break;
			}
		}
		if (found) {
			return (void *)(bytes + i);
		}
	}
	return nullptr;
}

// Wrapper:
void* PatternScanProcess(HANDLE hProc, uintptr_t begin, uintptr_t end, char* pattern, char* mask) {
	uintptr_t currentChunk = begin;
	SIZE_T bytesRead;

	while (currentChunk < end) {
		char buffer[4096];

		DWORD oldProtect;
		VirtualProtectEx(hProc, (void*)currentChunk, sizeof(buffer), PAGE_EXECUTE_READWRITE, &oldProtect);
		ReadProcessMemory(hProc, (void *)currentChunk, &buffer, sizeof(buffer), &bytesRead);
		VirtualProtectEx(hProc, (void *)currentChunk, sizeof(buffer), oldProtect, &oldProtect);

		if (bytesRead == 0) { return nullptr; }

		// Scan the current chunk of memory for the pattern we are looking for using PatternScan():
		void *internalAddress = PatternScan((char *)&buffer, bytesRead, pattern, mask);

		if (internalAddress != nullptr) {
			uintptr_t offsetFromBuffer = (uintptr_t)internalAddress - (uintptr_t)&buffer;
			return (void *)(currentChunk + offsetFromBuffer);
		} else {
			currentChunk = currentChunk + bytesRead;
		}
	}
	return nullptr;
}

// Wrapper for scanning modules:
void* PatternScanModule(HANDLE hProc, const std::string& procName, const std::string& modName, char* pattern, char* mask) {
	DWORD procID = GetProcID(procName);
	MODULEENTRY32 modEntry = GetModule(procID, modName);

	if (!modEntry.th32ModuleID) {
		return nullptr;
	}

	uintptr_t begin = (uintptr_t)modEntry.modBaseAddr;
	uintptr_t end = begin + modEntry.modBaseSize;
	return PatternScanProcess(hProc, begin, end, pattern, mask);
}