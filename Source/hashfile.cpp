//
//	hashfile.cpp
//
//	Calculate the SHA1 / SHA2 hash of a file using Windows APIs
//	On Windows Vista+, this supports the CNG
//	On Windows XP, this supports the CryptoAPI
//	SHA2 is supported on Windows XP SP3+
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

#define _WIN32_WINNT NTDDI_WINXPSP3 // Windows XP (SP3)

#if defined(_MSC_VER)
	// Disable run-time checks for debug builds (they require the CRT)
	#pragma runtime_checks( "", off ) 
#endif

#include "hashfile.h"
#include <Strsafe.h>
#include <bcrypt.h>		// For the CNG functions
#include <Wincrypt.h>	// For the CryptoAPI functions
#include "utils.h"

#define NT_SUCCESS(Status)          (((NTSTATUS)(Status)) >= 0)
#define STATUS_UNSUCCESSFUL         ((NTSTATUS)0xC0000001L)
#define FILE_READ_BUFFER_SIZE		(1024 * 8)

enum HashFileCNGErrorCodes
{
	ERR_SUCCESS = 0,
	ERR_CNG_API_UNAVAIABLE
};

// Bcrypt.dll

typedef NTSTATUS (WINAPI *PBCryptOpenAlgorithmProvider)(
	BCRYPT_ALG_HANDLE *phAlgorithm,
	LPCWSTR           pszAlgId,
	LPCWSTR           pszImplementation,
	DWORD             dwFlags
	);

typedef NTSTATUS (WINAPI *PBCryptGetProperty)(
	BCRYPT_HANDLE hObject,
	LPCWSTR       pszProperty,
	PUCHAR        pbOutput,
	ULONG         cbOutput,
	ULONG         *pcbResult,
	ULONG         dwFlags
	);

typedef NTSTATUS (WINAPI *PBCryptCreateHash)(
	BCRYPT_ALG_HANDLE  hAlgorithm,
	BCRYPT_HASH_HANDLE *phHash,
	PUCHAR             pbHashObject,
	ULONG              cbHashObject,
	PUCHAR             pbSecret,
	ULONG              cbSecret,
	ULONG              dwFlags
	);

typedef NTSTATUS (WINAPI *PBCryptHashData)(
	BCRYPT_HASH_HANDLE hHash,
	PUCHAR             pbInput,
	ULONG              cbInput,
	ULONG              dwFlags
	);

typedef NTSTATUS (WINAPI *PBCryptFinishHash)(
	BCRYPT_HASH_HANDLE hHash,
	PUCHAR             pbOutput,
	ULONG              cbOutput,
	ULONG              dwFlags
	);

typedef NTSTATUS (WINAPI *PBCryptDestroyHash)(
	BCRYPT_HASH_HANDLE hHash
	);

typedef NTSTATUS (WINAPI *PBCryptCloseAlgorithmProvider)(
	BCRYPT_ALG_HANDLE hAlgorithm,
	ULONG             dwFlags
	);

// Advapi32.dll

typedef BOOL (WINAPI *PCryptAcquireContext)(
	HCRYPTPROV *phProv,
	LPCTSTR    pszContainer,
	LPCTSTR    pszProvider,
	DWORD      dwProvType,
	DWORD      dwFlags
	);

typedef BOOL (WINAPI *PCryptCreateHash)(
	HCRYPTPROV hProv,
	ALG_ID     Algid,
	HCRYPTKEY  hKey,
	DWORD      dwFlags,
	HCRYPTHASH *phHash
	);

typedef BOOL (WINAPI *PCryptHashData)(
	HCRYPTHASH hHash,
	BYTE       *pbData,
	DWORD      dwDataLen,
	DWORD      dwFlags
	);

typedef BOOL (WINAPI *PCryptGetHashParam)(
	HCRYPTHASH hHash,
	DWORD      dwParam,
	BYTE       *pbData,
	DWORD      *pdwDataLen,
	DWORD      dwFlags
	);

typedef BOOL (WINAPI *PCryptDestroyHash)(
	HCRYPTHASH hHash
	);

typedef BOOL (WINAPI *PCryptReleaseContext)(
	HCRYPTPROV hProv,
	DWORD      dwFlags
	);

#ifdef UNICODE
#define _CryptAcquireContextFunc "CryptAcquireContextW"
#else
#define _CryptAcquireContextFunc "CryptAcquireContextA"
#endif

// Supports: SHA1, SHA256, SHA384, SHA512 (on Vista+ - uses newer API)
static int HashFile_CNG(LPCTSTR pFilename, HASH_ALGORITHM algorithm, LPTSTR &hash_out)
{
	int						retValue = -1;
	BCRYPT_ALG_HANDLE       hAlg = NULL;
	BCRYPT_HASH_HANDLE      hHash = NULL;
	NTSTATUS                status = STATUS_UNSUCCESSFUL;
	DWORD                   cbData = 0, cbHash = 0, cbHashObject = 0;
	PBYTE                   pbHashObject = NULL;
	PBYTE                   pbHash = NULL;
	HANDLE					hFile = INVALID_HANDLE_VALUE;
	LPVOID					pFileBuffer = NULL;
	BOOL					retReadFile = FALSE;
	DWORD					numberOfBytesRead = 0;

	// Attempt to dynamically load the CNG APIs
	HMODULE hBcryptModule = SafeLoadSystemLibrary(_T("Bcrypt.dll"));
	if (hBcryptModule == NULL)
	{
		// Can't load Bcrypt.dll - bail!
		return ERR_CNG_API_UNAVAIABLE;
	}
	PBCryptOpenAlgorithmProvider Func_BCryptOpenAlgorithmProvider = (PBCryptOpenAlgorithmProvider)GetProcAddress(hBcryptModule, "BCryptOpenAlgorithmProvider");
	if (Func_BCryptOpenAlgorithmProvider == NULL) return ERR_CNG_API_UNAVAIABLE;
	PBCryptGetProperty Func_BCryptGetProperty = (PBCryptGetProperty)GetProcAddress(hBcryptModule, "BCryptGetProperty");
	if (Func_BCryptGetProperty == NULL) return ERR_CNG_API_UNAVAIABLE;
	PBCryptCreateHash Func_BCryptCreateHash = (PBCryptCreateHash)GetProcAddress(hBcryptModule, "BCryptCreateHash");
	if (Func_BCryptCreateHash == NULL) return ERR_CNG_API_UNAVAIABLE;
	PBCryptHashData Func_BCryptHashData = (PBCryptHashData)GetProcAddress(hBcryptModule, "BCryptHashData");
	if (Func_BCryptHashData == NULL) return ERR_CNG_API_UNAVAIABLE;
	PBCryptFinishHash Func_BCryptFinishHash = (PBCryptFinishHash)GetProcAddress(hBcryptModule, "BCryptFinishHash");
	if (Func_BCryptFinishHash == NULL) return ERR_CNG_API_UNAVAIABLE;
	PBCryptDestroyHash Func_BCryptDestroyHash = (PBCryptDestroyHash)GetProcAddress(hBcryptModule, "BCryptDestroyHash");
	if (Func_BCryptDestroyHash == NULL) return ERR_CNG_API_UNAVAIABLE;
	PBCryptCloseAlgorithmProvider Func_BCryptCloseAlgorithmProvider = (PBCryptCloseAlgorithmProvider)GetProcAddress(hBcryptModule, "BCryptCloseAlgorithmProvider");
	if (Func_BCryptCloseAlgorithmProvider == NULL) return ERR_CNG_API_UNAVAIABLE;

	LPCWSTR algID = NULL;
	switch (algorithm)
	{
	case HASH_SHA1:
		algID = BCRYPT_SHA1_ALGORITHM;
		break;
	case HASH_SHA256:
		algID = BCRYPT_SHA256_ALGORITHM;
		break;
	case HASH_SHA384:
		algID = BCRYPT_SHA384_ALGORITHM;
		break;
	case HASH_SHA512:
		algID = BCRYPT_SHA512_ALGORITHM;
		break;
	default:
		retValue = -1;
		goto Cleanup;
	}

	// Open the file for reading
	hFile = CreateFile(pFilename,             // file to open
		GENERIC_READ,          // open for reading
		FILE_SHARE_READ,       // share for reading
		NULL,                  // default security
		OPEN_EXISTING,         // existing file only
		FILE_ATTRIBUTE_NORMAL, // normal file, synchronous mode
		NULL);                 // no attr. template

	if (hFile == INVALID_HANDLE_VALUE)
	{
		// Failed to open file for reading
		retValue = -1;
		goto Cleanup;
	}

	// Open an algorithm handle
	if (!NT_SUCCESS(status = Func_BCryptOpenAlgorithmProvider(&hAlg, algID, NULL, 0)))
	{
		// "Error: 0x%x returned by BCryptOpenAlgorithmProvider", status
		goto Cleanup;
	}

	// Get the size of the buffer to hold the hash object
	if (!NT_SUCCESS(status = Func_BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PBYTE)&cbHashObject, sizeof(DWORD), &cbData, 0)))
	{
		// "Error: 0x%x returned by BCryptGetProperty", status
		goto Cleanup;
	}

	// Allocate the hash object on the heap
	pbHashObject = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbHashObject);
	if (NULL == pbHashObject)
	{
		// Memory allocation failed
		goto Cleanup;
	}

	// Get the length of the hash
	if (!NT_SUCCESS(status = Func_BCryptGetProperty(hAlg, BCRYPT_HASH_LENGTH, (PBYTE)&cbHash, sizeof(DWORD), &cbData, 0)))
	{
		// "Error: 0x%x returned by BCryptGetProperty", status
		goto Cleanup;
	}

	// Allocate the hash buffer on the heap
	pbHash = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbHash);
	if (NULL == pbHash)
	{
		// Memory allocation failed
		goto Cleanup;
	}

	// Create a hash
	if (!NT_SUCCESS(status = Func_BCryptCreateHash(hAlg, &hHash, pbHashObject, cbHashObject, NULL, 0, 0)))
	{
		// "Error: 0x%x returned by BCryptCreateHash", status
		goto Cleanup;
	}

	// Allocate the file read buffer on the heap
	pFileBuffer = (LPVOID)HeapAlloc(GetProcessHeap(), 0, FILE_READ_BUFFER_SIZE);
	if (NULL == pFileBuffer)
	{
		// Memory allocation failed
		goto Cleanup;
	}

	// Hash the data from the file
	while ((retReadFile = ReadFile(hFile, pFileBuffer, FILE_READ_BUFFER_SIZE, &numberOfBytesRead, NULL)) != FALSE)
	{
		if (numberOfBytesRead == 0)
		{
			// Reached end of file
			break;
		}
		else
		{
			// Hash the file chunk
			if (!NT_SUCCESS(status = Func_BCryptHashData(hHash, (PBYTE)pFileBuffer, numberOfBytesRead, 0)))
			{
				// "Error: 0x%x returned by BCryptHashData", status
				goto Cleanup;
			}
		}
	}
	if (retReadFile == FALSE)
	{
		// Error reading file
		goto Cleanup;
	}

	// Close the hash
	if (!NT_SUCCESS(status = Func_BCryptFinishHash(hHash, pbHash, cbHash, 0)))
	{
		// "Error: 0x%x returned by BCryptFinishHash", status
		goto Cleanup;
	}

	// Create a hex string from the hash bytes
	hash_out = BytesToHexString(pbHash, cbHash);
	if (NULL == hash_out)
	{
		goto Cleanup;
	}
	else
	{
		// Successfully generated hash (as string)
		retValue = 0;
	}

Cleanup:

	if (hHash)
		Func_BCryptDestroyHash(hHash);
	if (hAlg)
		Func_BCryptCloseAlgorithmProvider(hAlg, 0);
	if (pbHashObject)
		HeapFree(GetProcessHeap(), 0, pbHashObject);
	if (pbHash)
		HeapFree(GetProcessHeap(), 0, pbHash);
	if (hFile != INVALID_HANDLE_VALUE)
		CloseHandle(hFile);
	if (pFileBuffer)
		HeapFree(GetProcessHeap(), 0, pFileBuffer);

	FreeLibrary(hBcryptModule);

	return retValue;
}

// Supports: SHA1 (on Windows XP, XP SP1, and XP SP2)
//			 SHA256, SHA384, SHA512 (on XP SP3, Vista+)
static int HashFile_CryptoAPI(LPCTSTR pFilename, HASH_ALGORITHM algorithm, LPTSTR &hash_out)
{
	int						retValue = -1;
	HCRYPTPROV				hCryptProv = NULL;
	HCRYPTHASH				hHash = NULL;
	DWORD                   dwBufferSize = 0, cbHash = 0;
	PBYTE                   pbHash = NULL;
	HANDLE					hFile = INVALID_HANDLE_VALUE;
	LPVOID					pFileBuffer = NULL;
	BOOL					retReadFile = FALSE;
	DWORD					numberOfBytesRead = 0;

	// Attempt to dynamically load all the CryptoAPI APIs
	HMODULE hAdvapi32Module = SafeLoadSystemLibrary(_T("Advapi32.dll"));
	if (hAdvapi32Module == NULL)
	{
		// Can't load Advapi32.dll - bail!
		return -1;
	}
	PCryptAcquireContext Func_CryptAcquireContext = (PCryptAcquireContext)GetProcAddress(hAdvapi32Module, _CryptAcquireContextFunc);
	if (Func_CryptAcquireContext == NULL) return -1;
	PCryptCreateHash Func_CryptCreateHash = (PCryptCreateHash)GetProcAddress(hAdvapi32Module, "CryptCreateHash");
	if (Func_CryptCreateHash == NULL) return -1;
	PCryptHashData Func_CryptHashData = (PCryptHashData)GetProcAddress(hAdvapi32Module, "CryptHashData");
	if (Func_CryptHashData == NULL) return -1;
	PCryptGetHashParam Func_CryptGetHashParam = (PCryptGetHashParam)GetProcAddress(hAdvapi32Module, "CryptGetHashParam");
	if (Func_CryptGetHashParam == NULL) return -1;
	PCryptDestroyHash Func_CryptDestroyHash = (PCryptDestroyHash)GetProcAddress(hAdvapi32Module, "CryptDestroyHash");
	if (Func_CryptDestroyHash == NULL) return -1;
	PCryptReleaseContext Func_CryptReleaseContext = (PCryptReleaseContext)GetProcAddress(hAdvapi32Module, "CryptReleaseContext");
	if (Func_CryptReleaseContext == NULL) return -1;

	LPCTSTR pszProvider = MS_DEF_PROV;
	LPCTSTR pszProvider_Fallback = NULL;
	DWORD dwProvType = PROV_RSA_FULL;
	ALG_ID algID = 0;
	switch (algorithm)
	{
	case HASH_SHA1:
		algID = CALG_SHA1;
		pszProvider = MS_DEF_PROV;
		pszProvider_Fallback = NULL;
		dwProvType = PROV_RSA_FULL;
		break;
	case HASH_SHA256:
		algID = CALG_SHA_256;
		pszProvider = MS_ENH_RSA_AES_PROV;
		pszProvider_Fallback = MS_ENH_RSA_AES_PROV_XP;
		dwProvType = PROV_RSA_AES;
		break;
	case HASH_SHA384:
		algID = CALG_SHA_384;
		pszProvider = MS_ENH_RSA_AES_PROV;
		pszProvider_Fallback = MS_ENH_RSA_AES_PROV_XP;
		dwProvType = PROV_RSA_AES;
		break;
	case HASH_SHA512:
		algID = CALG_SHA_512;
		pszProvider = MS_ENH_RSA_AES_PROV;
		pszProvider_Fallback = MS_ENH_RSA_AES_PROV_XP;
		dwProvType = PROV_RSA_AES;
		break;
	default:
		retValue = -1;
		goto Cleanup;
	}

	// Open the file for reading
	hFile = CreateFile(pFilename,             // file to open
		GENERIC_READ,          // open for reading
		FILE_SHARE_READ,       // share for reading
		NULL,                  // default security
		OPEN_EXISTING,         // existing file only
		FILE_ATTRIBUTE_NORMAL, // normal file, synchronous mode
		NULL);                 // no attr. template

	if (hFile == INVALID_HANDLE_VALUE)
	{
		// Failed to open file for reading
		retValue = -1;
		goto Cleanup;
	}

	if (Func_CryptAcquireContext(&hCryptProv, NULL, pszProvider, dwProvType, CRYPT_VERIFYCONTEXT) == FALSE)
	{
		// Attempt with fallback provider name
		if (Func_CryptAcquireContext(&hCryptProv, NULL, pszProvider_Fallback, dwProvType, CRYPT_VERIFYCONTEXT) == FALSE)
		{
			// CryptAcquireContext failed
			goto Cleanup;
		}
	}

	if (Func_CryptCreateHash(hCryptProv, algID, 0, 0, &hHash) == FALSE)
	{
		// CryptCreateHash failed
		goto Cleanup;
	}

	// Allocate the file read buffer on the heap
	pFileBuffer = (LPVOID)HeapAlloc(GetProcessHeap(), 0, FILE_READ_BUFFER_SIZE);
	if (NULL == pFileBuffer)
	{
		// Memory allocation failed
		goto Cleanup;
	}

	// Hash the data from the file
	while ((retReadFile = ReadFile(hFile, pFileBuffer, FILE_READ_BUFFER_SIZE, &numberOfBytesRead, NULL)) != FALSE)
	{
		if (numberOfBytesRead == 0)
		{
			// Reached end of file
			break;
		}
		else
		{
			//hash the file chunk
			if (Func_CryptHashData(hHash, (PBYTE)pFileBuffer, numberOfBytesRead, 0) == FALSE)
			{
				// CryptHashData failed
				goto Cleanup;
			}
		}
	}
	if (retReadFile == FALSE)
	{
		// Error reading file
		goto Cleanup;
	}

	// Get the length of the hash
	dwBufferSize = sizeof(DWORD);
	if (Func_CryptGetHashParam(hHash, HP_HASHSIZE, (BYTE*)&cbHash, &dwBufferSize, 0) == FALSE)
	{
		// CryptGetHashParam failed to get hash size
		goto Cleanup;
	}

	// Allocate the hash buffer on the heap
	pbHash = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbHash);
	if (NULL == pbHash)
	{
		// Memory allocation failed
		goto Cleanup;
	}

	// Get hash value
	if (Func_CryptGetHashParam(hHash, HP_HASHVAL, pbHash, &cbHash, 0) == FALSE)
	{
		// CryptGetHashParam failed
		goto Cleanup;
	}

	// Create a hex string from the hash bytes
	hash_out = BytesToHexString(pbHash, cbHash);
	if (NULL == hash_out)
	{
		goto Cleanup;
	}
	else
	{
		// Successfully generated hash (as string)
		retValue = 0;
	}

Cleanup:
	if (hHash)
		Func_CryptDestroyHash(hHash);
	if (hCryptProv)
		Func_CryptReleaseContext(hCryptProv, 0);
	if (pbHash)
		HeapFree(GetProcessHeap(), 0, pbHash);
	if (hFile != INVALID_HANDLE_VALUE)
		CloseHandle(hFile);
	if (pFileBuffer)
		HeapFree(GetProcessHeap(), 0, pFileBuffer);

	FreeLibrary(hAdvapi32Module);

	return retValue;
}

// Calculates the hash of a file
// If successful, a pointer to the newly-(heap)-allocated hash string is stored in hash_out.
// The caller is responsible for freeing the hash string by calling HeapFree(GetProcessHeap(), 0, hash_out).
// Returns: 0 if successful, non-0 if failed
extern "C" int HashFile(LPCTSTR pFilename, HASH_ALGORITHM algorithm, LPTSTR &hash_out)
{
	hash_out = NULL;

	// Attempt calculating hash using CNG (requires Vista+)
	int retVal = -1;
	if ((retVal = HashFile_CNG(pFilename, algorithm, hash_out)) == 0)
	{
		// Success!
		return 0;
	}
	else if (retVal == ERR_CNG_API_UNAVAIABLE)
	{
		// fall-back to older CryptoAPI
		if ((retVal = HashFile_CryptoAPI(pFilename, algorithm, hash_out)) == 0)
		{
			// Success with CryptoAPI fallback
			return 0;
		}
		else
		{
			// treat error as fatal
			return -1;
		}
	}
	else
	{
		// other error - treat as fatal
		return -1;
	}
}
