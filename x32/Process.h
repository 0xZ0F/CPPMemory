/*

	The process functions are used to gather information about processes, modules, etc.
	Code by Z0F.

*/

#pragma once
#include <Windows.h>
#include <TlHelp32.h>

// Get Process ID From an executable name using toolhelp32Snapshot:
DWORD GetProcID(const wchar_t* procName);

// Get ModuleEntry from module name, using toolhelp32snapshot:
MODULEENTRY32 GetModule(const DWORD& procID, const wchar_t* modName);