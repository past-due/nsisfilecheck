#include "utils.h"
#include <Strsafe.h>

#if defined(_MSC_VER)
	// Disable run-time checks for debug builds (they require the CRT)
	#pragma runtime_checks( "", off ) 
#endif

#if !defined(LOAD_LIBRARY_SEARCH_SYSTEM32)
#define LOAD_LIBRARY_SEARCH_SYSTEM32        0x00000800
#endif

// Safely load a system library
// Expectation: lpFileName is a filename
extern "C" HMODULE SafeLoadSystemLibrary(LPCTSTR lpFileName)
{
	HMODULE hKernel32 = GetModuleHandle(_T("kernel32"));
	if (hKernel32 == NULL)
	{
		return NULL;
	}

	// Check for the presence of AddDllDirectory as a proxy for checking whether
	// the LoadLibraryEx LOAD_LIBARY_SEARCH_SYSTEM32 flag is supported.
	// On Windows 8+, support is built-in.
	// On Windows 7, Windows Server 2008 R2, Windows Vista and Windows Server 2008,
	// support is available if KB2533623 is installed.
	if (GetProcAddress(hKernel32, "AddDllDirectory") != NULL)
	{
		// LOAD_LIBARY_SEARCH_SYSTEM32 is available
		return LoadLibraryEx(lpFileName, NULL, LOAD_LIBRARY_SEARCH_SYSTEM32);
	}
	else
	{
		// LOAD_LIBARY_SEARCH_SYSTEM32 is unavailable - attempt to create full path to system folder
		int fileNameLen = lstrlen(lpFileName);
		UINT sysDirLen = GetSystemDirectory(NULL, 0);
		if (sysDirLen == 0)
		{
			return NULL;
		}
		int totalStringLen = (sysDirLen + 1 + fileNameLen);
		TCHAR *sysDirStr = (TCHAR*)LocalAlloc(LPTR, totalStringLen * sizeof(TCHAR));
		if (sysDirStr == NULL)
		{
			return NULL;
		}
		if (GetSystemDirectory(sysDirStr, sysDirLen) == 0)
		{
			return NULL;
		}
		if (FAILED(StringCchCat(sysDirStr, totalStringLen, _T("\\"))))
		{
			return NULL;
		}
		if (FAILED(StringCchCat(sysDirStr, totalStringLen, lpFileName)))
		{
			return NULL;
		}
		HMODULE hModule = LoadLibraryEx(sysDirStr, NULL, LOAD_WITH_ALTERED_SEARCH_PATH);
		LocalFree(sysDirStr);
		return hModule;
	}
}

// Converts an ANSI LPCSTR to a (newly-allocated) LPCWSTR
// The caller is responsible for calling LocalFree() on the return value (if non-0) once finished
extern "C" LPWSTR ansitowstr(LPCSTR str)
{
	int outputStringCharacterLength = MultiByteToWideChar(CP_THREAD_ACP, 0, str, -1, 0, 0);
	if (outputStringCharacterLength == 0)
	{
		// Call to MultiByteToWideChar failed
		return 0;
	}
	WCHAR *outputString = (WCHAR*)LocalAlloc(LPTR, outputStringCharacterLength * sizeof(WCHAR));
	if (outputString == NULL)
	{
		// LocalAlloc failed
		return 0;
	}
	if (MultiByteToWideChar(CP_THREAD_ACP, 0, str, -1, outputString, outputStringCharacterLength) == 0)
	{
		// Call to MultiByteToWideChar failed
		LocalFree(outputString);
		return 0;
	}
	return outputString;
}

inline TCHAR NibbleToHexTCHAR(unsigned char nibble)
{
	TCHAR hexChar = 0;
	if (nibble < 10U)
	{
		hexChar = (TCHAR)(_T('0') + nibble);
	}
	else
	{
		nibble -= 10U;
		hexChar = (TCHAR)(_T('A') + nibble);
	}
	return hexChar;
}

// The caller is responsible for calling HeapFree(GetProcessHeap(), 0, <retVal>) on the return value (if non-NULL) once finished
extern "C" LPTSTR BytesToHexString(PBYTE pBytes, DWORD bytesLen)
{
	// convert the bytes to a hexidecimal string
	size_t strCharLen = ((bytesLen * 2) + 1);
	TCHAR* HexBytes = (TCHAR*)HeapAlloc(GetProcessHeap(), 0, strCharLen * sizeof(TCHAR));

	for (DWORD i = 0; i < bytesLen; ++i)
	{
		// The following is a verbose equivalent of:
		// StringCchPrintf(HexBytes + (i * 2), strCharLen - (i * 2), _T("%02X"), pBytes[i])
		// because StringCchPrintf won't work without linking to the CRT

		unsigned char firstNibble = (pBytes[i] >> 4);  // isolate first 4 bits
		TCHAR firstHexChar = NibbleToHexTCHAR(firstNibble);
		unsigned char secondNibble = (pBytes[i] & 0x0F);  // isolate last 4 bits
		TCHAR secondHexChar = NibbleToHexTCHAR(secondNibble);
		HexBytes[(i * 2)] = firstHexChar;
		HexBytes[(i * 2) + 1] = secondHexChar;
	}

	// ensure null terminator
	HexBytes[strCharLen - 1] = 0;

	return HexBytes;
}
