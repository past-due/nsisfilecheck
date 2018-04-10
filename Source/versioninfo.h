#pragma once
#ifndef ___VERSION_INFO__H___
#define ___VERSION_INFO__H___

#include <Windows.h>

#ifdef __cplusplus 
extern "C" {
#endif

// Retrieves a string value from the file version info of lptstrFilename.
// The caller is responsible for calling LocalFree() on the return value (if non-NULL) once finished
LPTSTR GetFileVersionString(LPCTSTR lptstrFilename, LPCTSTR stringName, WORD wLanguage = 1033, WORD wCodePage = 1252);

#ifdef __cplusplus
}
#endif

#endif//!___VERSION_INFO__H___
