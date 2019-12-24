#pragma once
#include <Windows.h>
#include <TlHelp32.h>
#include "Process.h"

//Internal Pattern Scan
void* PatternScan(char* base, size_t size, char* pattern, char* mask);

//External Wrapper
void* PatternScanEx(HANDLE hProc, uintptr_t begin, uintptr_t end, char* pattern, char* mask);

//Module wrapper for external pattern scan
void* PatternScanExModule(HANDLE hProc, wchar_t* exeName, wchar_t* module, char* pattern, char* mask);