//
//	versioninfo.cpp
//
//	Obtain details from the file version info
//
//	The MIT License
//
//	Copyright (c) 2018 pastdue  https://github.com/past-due/
//
//	Permission is hereby granted, free of charge, to any person obtaining a copy
//	of this software and associated documentation files (the "Software"), to deal
//	in the Software without restriction, including without limitation the rights
//	to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
//	copies of the Software, and to permit persons to whom the Software is
//	furnished to do so, subject to the following conditions:
//
//	The above copyright notice and this permission notice shall be included in
//	all copies or substantial portions of the Software.
//
//	THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
//	IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
//	FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
//	AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
//	LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
//	OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
//	THE SOFTWARE.
//
//

#include "versioninfo.h"
#include <Strsafe.h>
#include "utils.h"

typedef DWORD (WINAPI *PGetFileVersionInfoSize)(
	LPCTSTR lptstrFilename,
	LPDWORD lpdwHandle
);
#ifdef UNICODE
#define _GetFileVersionInfoSizeFunc "GetFileVersionInfoSizeW"
#else
#define _GetFileVersionInfoSizeFunc "GetFileVersionInfoSizeA"
#endif

typedef BOOL (WINAPI *PGetFileVersionInfo)(
	LPCTSTR lptstrFilename,
	DWORD dwHandle,
	DWORD dwLen,
	LPVOID lpData
);
#ifdef UNICODE
#define _GetFileVersionInfoFunc "GetFileVersionInfoW"
#else
#define _GetFileVersionInfoFunc "GetFileVersionInfoA"
#endif

typedef BOOL (WINAPI *PVerQueryValue)(
	LPCVOID pBlock,
	LPCTSTR lpSubBlock,
	LPVOID * lplpBuffer,
	PUINT puLen
);
#ifdef UNICODE
#define _VerQueryValueFunc "VerQueryValueW"
#else
#define _VerQueryValueFunc "VerQueryValueA"
#endif

#define STRINGFILEINFO_PREFIX _T("\\StringFileInfo\\")
#define STRINGFILEINFO_PREFIX_LEN 16

// Retrieves a string value from the file version info of lptstrFilename.
// The caller is responsible for calling LocalFree() on the return value (if non-NULL) once finished
extern "C" LPTSTR GetFileVersionString(LPCTSTR lptstrFilename, LPCTSTR stringName, WORD wLanguage /*= 1033*/, WORD wCodePage /*= 1252*/)
{
	LPTSTR retValue = NULL;
	void *pVersionInfoData = NULL;

	if (lptstrFilename == NULL) return NULL;
	if (stringName == NULL) return NULL;

	// Attempt to dynamically load the Version APIs
	HMODULE hVersionModule = SafeLoadSystemLibrary(_T("version.dll"));
	if (hVersionModule == NULL)
	{
		// Can't load version.dll - bail!
		return NULL;
	}
	PGetFileVersionInfoSize Func_GetFileVersionInfoSize = (PGetFileVersionInfoSize)GetProcAddress(hVersionModule, _GetFileVersionInfoSizeFunc);
	if (NULL == Func_GetFileVersionInfoSize) goto Cleanup;
	PGetFileVersionInfo Func_GetFileVersionInfo = (PGetFileVersionInfo)GetProcAddress(hVersionModule, _GetFileVersionInfoFunc);
	if (NULL == Func_GetFileVersionInfo) goto Cleanup;
	PVerQueryValue Func_VerQueryValue = (PVerQueryValue)GetProcAddress(hVersionModule, _VerQueryValueFunc);
	if (NULL == Func_VerQueryValue) goto Cleanup;

	DWORD lpThrowawayHandle = 0;
	DWORD versionInfoSize = Func_GetFileVersionInfoSize(lptstrFilename, &lpThrowawayHandle);
	if (0 == versionInfoSize)
	{
		goto Cleanup;
	}
	pVersionInfoData = (void*)LocalAlloc(LPTR, versionInfoSize);
	if (NULL == pVersionInfoData)
	{
		// Memory allocation failure
		goto Cleanup;
	}

	if (Func_GetFileVersionInfo(lptstrFilename, 0, versionInfoSize, pVersionInfoData) != 0)
	{
		// GetFileVersionInfo succeeded

		// The following is a verbose equivalent of:
		// StringCchPrintf(SubBlock, SubBlockLen, TEXT("\\StringFileInfo\\%04x%04x\\%s"), wLanguage, wCodePage, stringName)
		// because StringCchPrintf won't work without linking to the CRT

		LPTSTR wLanguageStr = WordToHexString(wLanguage);
		LPTSTR wCodePageStr = WordToHexString(wCodePage);
		const size_t SubBlockLen = MAX_PATH;
		TCHAR SubBlock[SubBlockLen];
		if (FAILED(StringCchCopy(SubBlock, SubBlockLen, STRINGFILEINFO_PREFIX)))
		{
			retValue = NULL;
			goto Cleanup;
		}
		if (FAILED(StringCchCat(SubBlock, SubBlockLen, wLanguageStr)))
		{
			retValue = NULL;
			goto Cleanup;
		}
		if (FAILED(StringCchCat(SubBlock, SubBlockLen, wCodePageStr)))
		{
			retValue = NULL;
			goto Cleanup;
		}
		if (FAILED(StringCchCat(SubBlock, SubBlockLen, _T("\\"))))
		{
			retValue = NULL;
			goto Cleanup;
		}
		if (FAILED(StringCchCat(SubBlock, SubBlockLen, stringName)))
		{
			retValue = NULL;
			goto Cleanup;
		}

		// Retrieve file description for language and code page. 
		LPCTSTR lpBuffer = NULL;
		UINT strLen = 0;
		if (Func_VerQueryValue(pVersionInfoData, SubBlock, (LPVOID *)&lpBuffer, &strLen) == 0)
		{
			retValue = NULL;
			goto Cleanup;
		}

		// Copy the string
		TCHAR *valueString = (TCHAR*)LocalAlloc(LPTR, (strLen + 1) * sizeof(TCHAR));
		if (valueString != NULL)
		{
			if (SUCCEEDED(StringCchCopy(valueString, strLen + 1, lpBuffer)))
			{
				retValue = valueString;
			}
		}
	}

Cleanup:
	if (pVersionInfoData) LocalFree(pVersionInfoData);

	FreeLibrary(hVersionModule);

	return retValue;
}
