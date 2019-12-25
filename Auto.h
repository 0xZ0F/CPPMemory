/*

	These functions are for QOL. They are pre-built functions for common tasks.
	Code by Z0F.

*/
#pragma once
#include "Process.h"
#include "Patching.h"
#include "Scanning.h"

// Size defaults to 0. If size is 0, then the size will automatically be computed.
void AutoWriteToAddress(const wchar_t* procName, void* dst, char* bytes, const unsigned int &size = 0);

// Size defaults to 0. If size is 0, then the size will automatically be computed.
void AutoWriteToOffset(const wchar_t* procName, wchar_t* modName, const unsigned int &offset, char* bytes, const unsigned int &size = 0);

// Size defaults to 0. If size is 0, then the size will automatically be computed.
void AutoWriteToPattern(const wchar_t* procName, wchar_t* modName, char* pattern, char* mask, char* bytes, const unsigned int &size = 0);