#pragma once
#include <Windows.h>

//internal patch
//void Patch(void* dst, void* src, unsigned int size);
//Internal Nop
//void Nop(HANDLE hProc, void* dest, unsigned int size);

// Will write to/patch starting at specified mem addr. Can write all R/W/X mem.
// External Patch: PatchEx(Proc Handle, Addr to write to, what to write, size of data to write);
void PatchEx(HANDLE &hProc, void* dst, char* bytes, const unsigned int &size);

//External Nop: NopEx(Proc Handle, Addr to start nops, num of nops);
void NopEx(HANDLE &hProc, void* dst, const unsigned int &size);