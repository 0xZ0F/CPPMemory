/*
	These functions are for QOL. They are pre-built functions for common tasks.
	Code by Z0F.
*/
#pragma once
#include "Process.h"
#include "Patching.h"
#include "Scanning.h"

void AutoWriteToAddress(const wchar_t* procName, void* dst, char* bytes, const unsigned int& size);

void AutoWriteToOffset(const wchar_t* procName, const wchar_t* modName, const unsigned int& offset, char* bytes, const unsigned int& size);

void AutoWriteToPattern(const wchar_t* procName, const wchar_t* modName, char* pattern, char* mask, char* bytes, const unsigned int& size);