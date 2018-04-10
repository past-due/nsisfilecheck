#pragma once
#ifndef ___UTILS__H___
#define ___UTILS__H___

#include <Windows.h>
#include "nsis/nsis_tchar.h"

#ifdef __cplusplus 
extern "C" {
#endif

// Safely load a system library
// Expectation: lpFileName is a filename
HMODULE SafeLoadSystemLibrary(LPCTSTR lpFileName);

// Converts an ANSI LPCSTR to a (newly-allocated) LPCWSTR
// The caller is responsible for calling LocalFree() on the return value (if non-0) once finished
LPWSTR ansitowstr(LPCSTR str);

// The caller is responsible for calling HeapFree(GetProcessHeap(), 0, <retVal>) on the return value (if non-NULL) once finished
LPTSTR BytesToHexString(PBYTE pBytes, DWORD bytesLen);

inline LPTSTR WordToHexString(WORD word)
{
	BYTE bytes[2];
	bytes[0] = (word >> 8) & 0xFF;
	bytes[1] = word & 0xFF;
	return BytesToHexString(bytes, 2);
}

#ifdef __cplusplus
}
#endif

#endif//!___UTILS__H___
