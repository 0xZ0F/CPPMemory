/*

	The process functions are used to gather information about processes, modules, etc.
	Code by Z0F.

*/

#pragma once
#include <Windows.h>
#include <TlHelp32.h>
#include <string>

// Get Process ID From an executable name using toolhelp32Snapshot:
DWORD GetProcID(const std::string& procName);

// Get ModuleEntry from module name, using toolhelp32snapshot:
MODULEENTRY32 GetModule(const DWORD& procID, const std::string& modName);