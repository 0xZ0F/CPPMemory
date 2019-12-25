#pragma once
#include "Process.h"
#include "Scanning.h"
#include "Patching.h"

void AutoWriteToAddress(const wchar_t* procName, void* dst, char* bytes, const unsigned int &size = 0);
void AutoWriteToOffset(const wchar_t* procName, wchar_t* modName, const unsigned int &offset, char* bytes, const unsigned int &size = 0);
void AutoWriteToPattern(const wchar_t* procName, wchar_t* modName, char* pattern, char* mask, char* bytes, const unsigned int &size = 0);