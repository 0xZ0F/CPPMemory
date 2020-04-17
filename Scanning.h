/*
	The pattern scanning functions are used to scan for patterns within a process.
	Question marks in a mask will account for changes in a binary such as addresses determined at runtime.
	The core of this code is by Fleep; Modified and optimized by Z0F.
*/

#pragma once
#include <Windows.h>
#include <TlHelp32.h>
#include "Process.h"

// Actual pattern scanning:
void* PatternScan(char* bytes, size_t size, char* pattern, char* mask);

// Wrapper:
void* PatternScanProcess(HANDLE hProc, uintptr_t begin, uintptr_t end, char* pattern, char* mask);

// Wrapper for scanning modules:
void* PatternScanModule(HANDLE hProc, const std::string& procName, const std::string& modName, char* pattern, char* mask);