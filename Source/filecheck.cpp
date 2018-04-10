//
//	filecheck.cpp
//
//	Contains the exported NSIS-compatible functions for
//	verifying / obtaining properties of files
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

#define _WIN32_WINNT 0x0501 // Windows XP+

#if defined(_MSC_VER)
	// Disable run-time checks for debug builds (they require the CRT)
	#pragma runtime_checks( "", off ) 
#endif

#include <windows.h>
#include "nsis/pluginapi.h"
#include <Strsafe.h>
#include "codesigncheck.h"
#include "hashfile.h"
#include "versioninfo.h"

HINSTANCE g_hInstance;
HWND g_hwndParent;

#ifndef COUNTOF
#define COUNTOF(a) (sizeof(a)/sizeof(a[0]))
#endif

// Code signature verification string output
static TCHAR szStatus[][64] = {
	_T("OK"),
	_T("Error: Failure Verifying Trust"),
	_T("Error: Not Microsoft Root"),
	_T("Error: Failed to Fetch Cert Details"),
	_T("Error: Cert Name Does Not Match"),
	_T("Error: Cert Issuer Name Does Not Match"),
	_T("Error: LoadLibrary Failure"),
	_T("Error: GetProcAddress Failure"),
	_T("Error: WTHelper* Func Failure"),
	_T("Error: Non-specific")
};

// Forward-declare from crt.cpp
extern "C" void* __cdecl crtless_memset(void *p, int c, size_t z);

// file hashing entry point
// (exported function for NSIS)
extern "C"
void __declspec(dllexport) __cdecl calcFileHash(HWND hwndParent,
	int string_size,
	TCHAR *variables,
	stack_t **stacktop,
	extra_parameters *extra
)
{
	// Input parameters on the stack are the filepath (first string) and then an algorithm - both are required
	LPCTSTR retString = NULL;
	TCHAR *filePath = NULL;
	TCHAR *algorithmString = NULL;
	HASH_ALGORITHM algorithm = HASH_SHA256;
	LPTSTR hashString = NULL;

	EXDLL_INIT();
	g_hwndParent = hwndParent;

	// Allocate buffer for the filepath
	filePath = (TCHAR*)LocalAlloc(LPTR, string_size * sizeof(TCHAR));
	if (filePath == NULL)
	{
		// LocalAlloc failed
		retString = _T("Error: Allocating Memory");
		goto Cleanup;
	}

	// First expected parameter is the filepath
	if (popstring(filePath) != 0)
	{
		// Missing required first parameter
		retString = _T("Input Error: Missing Required FilePath");
		goto Cleanup;
	}

	// Allocate temporary buffer for the algorithm string
	algorithmString = (TCHAR*)LocalAlloc(LPTR, string_size * sizeof(TCHAR));
	if (algorithmString == NULL)
	{
		// LocalAlloc failed
		retString = _T("Error: Allocating Memory");
		goto Cleanup;
	}

	// Second expected parameter is the algorithm
	if (popstring(algorithmString) != 0)
	{
		// Missing required first parameter
		retString = _T("Input Error: Missing Required Algorithm");
		goto Cleanup;
	}

	if ((lstrcmpi(algorithmString, _T("sha1")) == 0) || (lstrcmpi(algorithmString, _T("sha")) == 0))
	{
		algorithm = HASH_SHA1;
	}
	else if (lstrcmpi(algorithmString, _T("sha256")) == 0)
	{
		algorithm = HASH_SHA256;
	}
	else if (lstrcmpi(algorithmString, _T("sha384")) == 0)
	{
		algorithm = HASH_SHA384;
	}
	else if (lstrcmpi(algorithmString, _T("sha512")) == 0)
	{
		algorithm = HASH_SHA512;
	}
	else
	{
		// Unsupported algorithm
		retString = _T("Input Error: Unsupported Algorithm");
		goto Cleanup;
	}

	// calculate the file hash
	if (HashFile(filePath, algorithm, hashString) != 0)
	{
		// HashFile failed
		hashString = NULL;
		retString = _T("Error: Failed Calculating the File Hash");
		goto Cleanup;
	}
	retString = hashString;

Cleanup:
	if (filePath) LocalFree(filePath);
	if (algorithmString) LocalFree(algorithmString);

	// push the result (as a string) onto the stack
	if (NULL == retString)
	{
		retString = _T("Error: Unknown");
	}
	pushstring(retString);

	// must clean-up the hashString *after* pushing retString to the stack
	// because retString may be set to hashString
	if (hashString) HeapFree(GetProcessHeap(), 0, hashString);
}

// code signature verification entry point
// (exported function for NSIS)
extern "C"
void __declspec(dllexport) __cdecl verifyFileSignature( HWND hwndParent,
														int string_size,
														TCHAR *variables,
														stack_t **stacktop,
														extra_parameters *extra
														)
{
	LPCTSTR retString = NULL;
	TCHAR *filePath = NULL;
	TCHAR *parameter = NULL;
	bool microsoftRootCheck = false;
	TCHAR *certName = NULL;
	TCHAR *certIssuerName = NULL;

	EXDLL_INIT();
	g_hwndParent = hwndParent;

	// Allocate buffer for the filepath
	filePath = (TCHAR*)LocalAlloc(LPTR, string_size * sizeof(TCHAR));
	if (filePath == NULL)
	{
		// LocalAlloc failed
		retString = _T("Error: Allocating Memory");
		goto Cleanup;
	}

	// First expected parameter is the filepath
	if (popstring(filePath) != 0)
	{
		// Missing required first parameter
		retString = _T("Input Error: Missing Required FilePath");
		goto Cleanup;
	}

	// Allocate buffer for obtaining stack parameters
	parameter = (TCHAR*)LocalAlloc(LPTR, string_size * sizeof(TCHAR));
	if (parameter == NULL)
	{
		// LocalAlloc failed
		retString = _T("Error: Allocating Memory");
		goto Cleanup;
	}

	// pop from stack until we reach the end of possible parameters for this call
	while((popstring(parameter) == 0) && *parameter == _T('/'))
	{
		if(lstrcmpi(parameter, _T("/root")) == 0)
		{
			TCHAR *rootValue = (TCHAR*)LocalAlloc(LPTR, string_size * sizeof(TCHAR));
			popstring(rootValue);
			if(lstrcmpi(rootValue, _T("microsoft")) == 0)
			{
				microsoftRootCheck = true;
			}
			else
			{
				// Unsupported root specifier
				LocalFree(rootValue);
				retString = _T("Input Error: Unsupported /root value");
				goto Cleanup;
			}
			LocalFree(rootValue);
		}
		else if(lstrcmpi(parameter, _T("/certname")) == 0)
		{
			certName = (TCHAR*)LocalAlloc(LPTR, string_size * sizeof(TCHAR));
			if (popstring(certName) != 0)
			{
				// Missing certname value
				retString = _T("Input Error: Missing /certname value");
				goto Cleanup;
			}
		}
		else if(lstrcmpi(parameter, _T("/certissuername")) == 0)
		{
			certIssuerName = (TCHAR*)LocalAlloc(LPTR, string_size * sizeof(TCHAR));
			if (popstring(certIssuerName) != 0)
			{
				// Missing certissuername value
				retString = _T("Input Error: Missing /certissuername value");
				goto Cleanup;
			}
		}
	}
	pushstring(parameter); // push last parameter back on the stack

	// Verify code signature
	int verifyStatus = VerifyFileCodeSignature(filePath, certName, certIssuerName, microsoftRootCheck);
	retString = szStatus[verifyStatus];

Cleanup:
	// clear the stack (until "/end" is found)
	while((popstring(parameter) == 0) && lstrcmpi(parameter, _T("/end")) != 0)
	{
		/* nothing */
	}
	if (filePath) LocalFree(filePath);
	if (parameter) LocalFree(parameter);
	if (certName) LocalFree(certName);
	if (certIssuerName) LocalFree(certIssuerName);

	// push the result (as a string) onto the stack
	if (NULL == retString)
	{
		retString = _T("Error: Unknown");
	}
	pushstring(retString);
}

// file version info string entry point
// (exported function for NSIS)
extern "C"
void __declspec(dllexport) __cdecl getFileVersionInfoString(HWND hwndParent,
	int string_size,
	TCHAR *variables,
	stack_t **stacktop,
	extra_parameters *extra
)
{
	LPCTSTR retString = NULL;
	TCHAR *filePath = NULL;
	TCHAR *stringName = NULL;
	TCHAR *parameter = NULL;
	WORD wLanguage = 1033;
	WORD wCodepage = 1252;
	LPTSTR versionInfoValue = NULL;

	EXDLL_INIT();
	g_hwndParent = hwndParent;

	// Allocate buffer for the filepath
	filePath = (TCHAR*)LocalAlloc(LPTR, string_size * sizeof(TCHAR));
	if (filePath == NULL)
	{
		// LocalAlloc failed
		retString = _T("Error: Allocating Memory");
		goto Cleanup;
	}

	// First expected parameter is the filepath
	if (popstring(filePath) != 0)
	{
		// Missing required first parameter
		retString = _T("Input Error: Missing Required FilePath");
		goto Cleanup;
	}

	// Allocate buffer for the stringName
	stringName = (TCHAR*)LocalAlloc(LPTR, string_size * sizeof(TCHAR));
	if (stringName == NULL)
	{
		// LocalAlloc failed
		retString = _T("Error: Allocating Memory");
		goto Cleanup;
	}

	// Second expected parameter is the stringName
	if (popstring(stringName) != 0)
	{
		// Missing required first parameter
		retString = _T("Input Error: Missing Required StringName");
		goto Cleanup;
	}

	// Allocate buffer for obtaining additional stack parameters
	parameter = (TCHAR*)LocalAlloc(LPTR, string_size * sizeof(TCHAR));
	if (parameter == NULL)
	{
		// LocalAlloc failed
		retString = _T("Error: Allocating Memory");
		goto Cleanup;
	}

	// check for (optional) parameters
	// pop from stack until we reach the end of possible parameters for this call
	while ((popstring(parameter) == 0) && *parameter == _T('/'))
	{
		if (lstrcmpi(parameter, _T("/language")) == 0)
		{
			int language = popint();
			if (language > USHRT_MAX)
			{
				// language value is greater than the max value of a WORD
				retString = _T("Input Error: /language value is too large");
				goto Cleanup;
			}
			wLanguage = language;
		}
		else if (lstrcmpi(parameter, _T("/codepage")) == 0)
		{
			int codepage = popint();
			if (codepage > USHRT_MAX)
			{
				// language value is greater than the max value of a WORD
				retString = _T("Input Error: /codepage value is too large");
				goto Cleanup;
			}
			wCodepage = codepage;
		}
	}
	pushstring(parameter); // push last parameter back on the stack

	versionInfoValue = GetFileVersionString(filePath, stringName, wLanguage, wCodepage);
	if (versionInfoValue != NULL)
	{
		retString = versionInfoValue;
	}

Cleanup:
	// clear the stack (until "/end" is found)
	while ((popstring(parameter) == 0) && lstrcmpi(parameter, _T("/end")) != 0)
	{
		/* nothing */
	}
	if (filePath) LocalFree(filePath);
	if (stringName) LocalFree(stringName);
	if (parameter) LocalFree(parameter);

	// push the result (as a string) onto the stack
	if (NULL == retString)
	{
		retString = _T("Error: Unknown");
	}
	pushstring(retString);

	// must clean-up the versionInfoValue *after* pushing retString to the stack
	// because retString may be set to versionInfoValue
	if (versionInfoValue) LocalFree(versionInfoValue);
}

// DllMain() (initialization) entry point
#ifdef _VC_NODEFAULTLIB
#define DllMain _DllMainCRTStartup
#endif
EXTERN_C BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
	g_hInstance = hinstDLL;
	return TRUE;
}
