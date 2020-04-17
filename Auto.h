/*
	These functions are for QOL. They are pre-built functions for common tasks.
	Code by Z0F.
*/
#pragma once
#include <string>
#include "Process.h"
#include "Patching.h"
#include "Scanning.h"

void AutoWriteToAddress(const std::string& procName, void* dst, char* bytes, const unsigned int& size);

void AutoWriteToOffset(const std::string& procName, const std::string& modName, const unsigned int& offset, char* bytes, const unsigned int& size);

void AutoWriteToPattern(const std::string& procName, const std::string& modName, char* pattern, char* mask, char* bytes, const unsigned int& size);