#include <Windows.h>
#include <TlHelp32.h>
#include <string>

namespace Memory {
	/*
		--------------------- Process ---------------------
	*/
	// Get PID given name:
	DWORD GetProcID(const std::string& procName) {
		PROCESSENTRY32 procEntry;
		procEntry.dwSize = sizeof(procEntry);

		HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);

		if (Process32First(hSnapshot, &procEntry)) {
			do {
				if (strcmp(procEntry.szExeFile, procName.c_str()) == 0) {
					CloseHandle(hSnapshot);
					return procEntry.th32ProcessID;
				}
			} while (Process32Next(hSnapshot, &procEntry));
			CloseHandle(hSnapshot);
		}
		return 0;
	}
	// Get ModuleEntry from module name, using toolhelp32snapshot:
	MODULEENTRY32 GetModule(const DWORD& procID, const std::string& modName) {
		MODULEENTRY32 modEntry = { 0 };

		HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, procID);

		if (hSnapshot != INVALID_HANDLE_VALUE) {
			MODULEENTRY32 curr = { 0 };
			curr.dwSize = sizeof(MODULEENTRY32);

			if (Module32First(hSnapshot, &curr)) {
				do {
					if (curr.szModule == modName) {
						modEntry = curr;
						break;
					}
				} while (Module32Next(hSnapshot, &curr));
			}
			CloseHandle(hSnapshot);
		}
		return modEntry;
	}

	/*
		--------------------- Patching ---------------------
	*/
	// Write mem:
	void Patch(HANDLE& hProc, void* dst, char* bytes, const unsigned int& size) {
		DWORD oldProtect;
		VirtualProtectEx(hProc, dst, size, PAGE_EXECUTE_READWRITE, &oldProtect); // PAGE_READWRITE
		WriteProcessMemory(hProc, dst, bytes, size, NULL);
		VirtualProtectEx(hProc, dst, size, oldProtect, &oldProtect);
	}
	// Write NOPs:
	void Nop(HANDLE& hProc, void* dst, const unsigned int& size) {
		byte* nopArray = new byte[size];
		memset(nopArray, 0x90, size);
		DWORD oldProtect;

		VirtualProtectEx(hProc, dst, size, PAGE_EXECUTE_READWRITE, &oldProtect);
		WriteProcessMemory(hProc, dst, nopArray, size, NULL);
		VirtualProtectEx(hProc, dst, size, oldProtect, &oldProtect);
		delete[] nopArray;
	}

	/*
		--------------------- Scanning ---------------------
	*/
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
				return (void*)(bytes + i);
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
			ReadProcessMemory(hProc, (void*)currentChunk, &buffer, sizeof(buffer), &bytesRead);
			VirtualProtectEx(hProc, (void*)currentChunk, sizeof(buffer), oldProtect, &oldProtect);

			if (bytesRead == 0) { return nullptr; }

			// Scan the current chunk of memory for the pattern we are looking for using PatternScan():
			void* internalAddress = PatternScan((char*)&buffer, bytesRead, pattern, mask);

			if (internalAddress != nullptr) {
				uintptr_t offsetFromBuffer = (uintptr_t)internalAddress - (uintptr_t)&buffer;
				return (void*)(currentChunk + offsetFromBuffer);
			}
			else {
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

	/*
		--------------------- Autos ---------------------
	*/
	void AutoWriteToAddress(const std::string& procName, void* dst, char* bytes, const unsigned int& size) {
		DWORD procID = GetProcID(procName);
		HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, false, procID);

		Patch(hProc, dst, bytes, ((size == 0) ? sizeof(bytes) : size));
	}

	void AutoWriteToOffset(const std::string& procName, const std::string& modName, const unsigned int& offset, char* bytes, const unsigned int& size) {
		DWORD procID = GetProcID(procName);
		HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, false, procID);

		MODULEENTRY32 modEntry = GetModule(procID, modName);
		if (!modEntry.th32ModuleID) { return; }

		Patch(hProc, (void*)((uintptr_t)modEntry.modBaseAddr + offset), bytes, ((size == 0) ? sizeof(bytes) : size));
	}

	void AutoWriteToPattern(const std::string& procName, const std::string& modName, char* pattern, char* mask, char* bytes, const unsigned int& size) {
		DWORD procID = GetProcID(procName);
		HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, false, procID);

		void* patternAddr = PatternScanModule(hProc, procName, modName, pattern, mask);

		if (patternAddr != nullptr) {
			Patch(hProc, patternAddr, bytes, ((size == 0) ? sizeof(bytes) : size));
		}
	}
}