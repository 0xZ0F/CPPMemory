/*

	The pattern scanning functions are used to scan for patterns within a process.
	Question marks in a mask will account for changes in a binary such as hard-coded addresses determined at runtime.
	Code by Z0F.

*/

#pragma once
#include <Windows.h>
#include <TlHelp32.h>
#include "Process.h"

// Internal Pattern Scan:
void* PatternScan(char* base, size_t size, char* pattern, char* mask);

// External Wrapper:
void* PatternScanProcess(HANDLE hProc, uintptr_t begin, uintptr_t end, char* pattern, char* mask);

// Module wrapper for external pattern scan:
void* PatternScanModule(HANDLE hProc, const wchar_t* procName, wchar_t* modName, char* pattern, char* mask);