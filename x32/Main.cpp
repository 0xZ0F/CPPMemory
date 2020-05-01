/*

    Main.cpp (this file) is NOT needed, it's a good place to put your code and can be used as a reference.
    Code by Z0F.

*/

#include <Windows.h>
#include <iostream>
#include "Process.h"
#include "Scanning.h"
#include "Patching.h"
#include "Auto.h"
#include "_MemoryOneHeader.h"
#define Log(x) std::cout << x << std::endl;
#define Hex(x) std::cout << std::hex << x << std::endl;


int main() {
    DWORD procID = GetProcID(L"Testing.exe");
    MODULEENTRY32 mod = GetModule(procID, L"Testing.exe");
    std::cout << mod.dwSize << std::endl;
    mod = GetModule(procID, L"fsdf.exe");
    std::cout << mod.dwSize << std::endl;

    std::getchar();
}

// Example Functions:
static void Example_WriteToAddr() {
    // Get proc ID:
    DWORD procID = GetProcID(L"Testing.exe");
    std::cout << "Process ID: " << procID << std::endl;
    // Get proc handle:
    HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, false, procID);

    // Write bytes at addr 0x00007FF625631EEA:
    Patch(hProc, (void *)(0x00007FF697DB1EEA), "\xC7\x44\x24\x40\x0F\x00\x00\x00", 8);
}

static void Example_WriteToOffset() {
    // Get proc ID:
    DWORD procID = GetProcID(L"Testing.exe");
    std::cout << "Process ID: " << procID << std::endl;
    // Get proc handle:
    HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, false, procID);

    // Get module entry address:
    MODULEENTRY32 modEntry = GetModule(procID, L"Testing.exe");
    if (!modEntry.th32ModuleID) { return; }

    // Write bytes at base + offset (modEntry.modBaseAddr + 0x1EEA):
    Patch(hProc, (void*)((uintptr_t)modEntry.modBaseAddr + 0x1EEA), "\xC7\x44\x24\x40\x0F\x00\x00\x00", 8);
}

static void Example_WriteToPattern() {
    // Get proc ID:
    DWORD procID = GetProcID(L"Testing.exe");
    std::cout << "Process ID: " << procID << std::endl;
    // Get proc handle:
    HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, false, procID);

    // Scan for the pattern of bytes with a mask/key of xxxx??xxxxx?x????xxxx?xxxx?xxxx????:
    void *patternAddr = PatternScanModule(hProc, L"Testing.exe", L"Testing.exe", "\x8B\x01\x3B\xC2\x7D\x03\x32\xC0\xC3\x2B\xC2\x89\x01\xB0\x01\xC3\xCC\x48\x89\x5C\x24\x08\x57\x48\x83\xEC\x20\x48\x8B\xF9\xE8\x0E\x3C\xF8\xFF", "xxxx??xxxxx?x????xxxx?xxxx?xxxx????");

    // Write bytes to the address found by the pattern scan:
    if (patternAddr != nullptr) {
        Patch(hProc, patternAddr, "\x8B\x01\x3B\xC2\x7D\x03\x32\xC0\xC3\x2B\xC2\xC7\x01\x00\x94\x35\x77\x48\x89\x5C\x24\x08\x57\x48\x83\xEC\x20\x48\x8B\xF9\xE8\x0E\x3C\xF8\xFF", 35);
    }
}

static void Example_ReadProcessMemory() {
    // https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-readprocessmemory

    DWORD procID = GetProcID(L"Testing.exe");
    HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, false, procID);

    MODULEENTRY32 modEntry = GetModule(procID, L"Testing.exe");

    // Array of bytes to put the memory in.
    int buffer = 0;

    // Read the memory and put it in buffer.
    // Reading BaseAddress of program + 0x112F
    ReadProcessMemory(hProc, (LPCVOID)(0x00007FF7A8A31EEA), &buffer, sizeof(int), NULL);
}