//
//	codesigncheck.cpp
//
//	Verify the Authenticode signature in a file (ex. EXE or DLL)
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

#include "codesigncheck.h"
#include <windows.h>
#include <Softpub.h>
#include <Strsafe.h>
#include <Wincrypt.h>
#include "utils.h"

// Forward-declare from crt.cpp
extern "C" void* __cdecl crtless_memset(void *p, int c, size_t z);

// TypeDefs for required WinAPI functions

// Wintrust.dll

typedef CRYPT_PROVIDER_DATA* (WINAPI *PWTHelperProvDataFromStateData)(
	HANDLE hStateData
);

typedef CRYPT_PROVIDER_SGNR* (WINAPI *PWTHelperGetProvSignerFromChain)(
	CRYPT_PROVIDER_DATA *pProvData,
	DWORD idxSigner,
	BOOL fCounterSigner,
	DWORD idxCounterSigner
);

typedef CRYPT_PROVIDER_CERT* (WINAPI *PWTHelperGetProvCertFromChain)(
	CRYPT_PROVIDER_SGNR *pSgnr,
	DWORD idxCert
);

typedef LONG (WINAPI *PWinVerifyTrust)(
	HWND hWnd,
	GUID *pgActionID,
	LPVOID pWVTData
);

// Crypt32.dll

typedef BOOL (WINAPI *PCertVerifyCertificateChainPolicy)(
	LPCSTR                    pszPolicyOID,
	PCCERT_CHAIN_CONTEXT      pChainContext,
	PCERT_CHAIN_POLICY_PARA   pPolicyPara,
	PCERT_CHAIN_POLICY_STATUS pPolicyStatus
);

typedef DWORD (WINAPI *PCertGetNameString)(
	PCCERT_CONTEXT pCertContext,
	DWORD          dwType,
	DWORD          dwFlags,
	void           *pvTypePara,
	LPTSTR         pszNameString,
	DWORD          cchNameString
);

// Verifies that a certificate chain ends in a Microsoft Root
static bool CertChainMicrosoftRootVerify(HMODULE hCrypt32Module,
										 PCCERT_CHAIN_CONTEXT pChainContext)
{
	PCertVerifyCertificateChainPolicy Func_CertVerifyCertificateChainPolicy = (PCertVerifyCertificateChainPolicy)GetProcAddress(hCrypt32Module, "CertVerifyCertificateChainPolicy");
	if (Func_CertVerifyCertificateChainPolicy == NULL) return false;

	CERT_CHAIN_POLICY_PARA ChainPolicyPara;
	crtless_memset(&ChainPolicyPara, 0, sizeof(CERT_CHAIN_POLICY_PARA));
	ChainPolicyPara.cbSize = sizeof(CERT_CHAIN_POLICY_PARA);
	ChainPolicyPara.dwFlags = 0;
	CERT_CHAIN_POLICY_STATUS ChainPolicyStatus;
	crtless_memset(&ChainPolicyStatus, 0, sizeof(CERT_CHAIN_POLICY_STATUS));

	if (Func_CertVerifyCertificateChainPolicy(CERT_CHAIN_POLICY_MICROSOFT_ROOT, pChainContext, &ChainPolicyPara, &ChainPolicyStatus) == TRUE)
	{
		// CertVerifyCertificateChainPolicy was able to check the policy
		// *Must* check ChainPolicyStatus.dwError to determine if the policy check was actually satisfied
		return ChainPolicyStatus.dwError == 0;
	}
	else
	{
		// CertVerifyCertificateChainPolicy failed to check the policy
		return false;
	}
}

// Calls CertGetNameString with the specified parameters, allocating an appropriately-sized buffer
// for the result. This buffer is then returned (if the calls were successful). NULL is returned on failure.
// The caller is responsible for calling LocalFree() on the return value (if non-NULL) once finished
static LPTSTR CertGetNameStringWrapper(PCertGetNameString Func_CertGetNameString,
										PCCERT_CONTEXT pCertContext,
										DWORD dwType,
										DWORD dwFlags,
										void *pvTypePara)
{
	int nLength = Func_CertGetNameString(pCertContext, dwType, dwFlags, pvTypePara, NULL, 0);
	if (nLength <= 0)
	{
		// Unable to get the length of the issuer-name string
		return NULL;
	}

	TCHAR *strBuffer = (TCHAR*)LocalAlloc(LPTR, nLength * sizeof(TCHAR));
	if (strBuffer == NULL)
	{
		// LocalAlloc failed
		return NULL;
	}

	if (!Func_CertGetNameString(pCertContext, dwType, dwFlags, pvTypePara, strBuffer, nLength))
	{
		LocalFree(strBuffer);
		return NULL;
	}

	return strBuffer;
}

#ifdef UNICODE
	#define _CertGetNameStringFunc "CertGetNameStringW"
#else
	#define _CertGetNameStringFunc "CertGetNameStringA"
#endif

static int VerifyStateDetails(HMODULE hWinTrustModule,
							  HMODULE hCrypt32Module,
							  HANDLE hWVTStateData,
							  const TCHAR * certName,
							  const TCHAR * certIssuerName,
							  bool microsoftRootCheck)
{
	PWTHelperProvDataFromStateData Func_WTHelperProvDataFromStateData = (PWTHelperProvDataFromStateData)GetProcAddress(hWinTrustModule, "WTHelperProvDataFromStateData");
	PWTHelperGetProvSignerFromChain Func_WTHelperGetProvSignerFromChain = (PWTHelperGetProvSignerFromChain)GetProcAddress(hWinTrustModule, "WTHelperGetProvSignerFromChain");
	PWTHelperGetProvCertFromChain Func_WTHelperGetProvCertFromChain = (PWTHelperGetProvCertFromChain)GetProcAddress(hWinTrustModule, "WTHelperGetProvCertFromChain");
	if (Func_WTHelperProvDataFromStateData == NULL) return ERROR_GETPROCADDRESSFAILURE;
	if (Func_WTHelperGetProvSignerFromChain == NULL) return ERROR_GETPROCADDRESSFAILURE;
	if (Func_WTHelperGetProvCertFromChain == NULL) return ERROR_GETPROCADDRESSFAILURE;

	PCertGetNameString Func_CertGetNameString = (PCertGetNameString)GetProcAddress(hCrypt32Module, _CertGetNameStringFunc);
	if (Func_CertGetNameString == NULL) return ERROR_GETPROCADDRESSFAILURE;

	CRYPT_PROVIDER_DATA *pCryptProvData = Func_WTHelperProvDataFromStateData(hWVTStateData);
	if (pCryptProvData == NULL) return ERROR_WTHELPERFAILED;
	CRYPT_PROVIDER_SGNR *pSigner = Func_WTHelperGetProvSignerFromChain(pCryptProvData, 0, FALSE, 0);
	if (pSigner == NULL) return ERROR_WTHELPERFAILED;

	if (microsoftRootCheck)
	{
		if (!CertChainMicrosoftRootVerify(hCrypt32Module, pSigner->pChainContext))
		{
			// Failed to verify Microsoft Root
			return ERROR_NOTMICROSOFTROOT;
		}
	}

	if (certName || certIssuerName)
	{
		CRYPT_PROVIDER_CERT *pCert = Func_WTHelperGetProvCertFromChain(pSigner, 0);
		if (pCert == NULL) return ERROR_WTHELPERFAILED;

		if (certName)
		{
			LPTSTR retrieved_CertName = CertGetNameStringWrapper(Func_CertGetNameString, pCert->pCert, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, NULL);
			if (retrieved_CertName == NULL)
			{
				return ERROR_CERTDETAILFETCHFAILED;
			}
			else
			{
				int retVal = lstrcmp(certName, retrieved_CertName);
				LocalFree(retrieved_CertName);
				if (retVal != 0)
				{
					return ERROR_CERTNAMENOTEQUAL;
				}
			}
		}

		if (certIssuerName)
		{
			LPTSTR retrieved_IssuerName = CertGetNameStringWrapper(Func_CertGetNameString, pCert->pCert, CERT_NAME_SIMPLE_DISPLAY_TYPE, CERT_NAME_ISSUER_FLAG, NULL);
			if (retrieved_IssuerName == NULL)
			{
				return ERROR_CERTDETAILFETCHFAILED;
			}
			else
			{
				int retVal = lstrcmp(certIssuerName, retrieved_IssuerName);
				LocalFree(retrieved_IssuerName);
				if (retVal != 0)
				{
					return ERROR_CERTISSUERNAMENOTEQUAL;
				}
			}
		}
	}

	return STATUS_OK;
}

extern "C" int VerifyFileCodeSignature( const TCHAR * filePath,
										const TCHAR * certName,
										const TCHAR * certIssuerName,
										bool microsoftRootCheck )
{
	if (filePath == NULL) return ERROR_NONSPECIFIC;

	HMODULE hWinTrustModule = SafeLoadSystemLibrary(_T("wintrust.dll"));
	if (hWinTrustModule == NULL)
	{
		// Can't load wintrust.dll - bail!
		return ERROR_LOADLIBRARYFAILURE;
	}
	HMODULE hCrypt32Module = SafeLoadSystemLibrary(_T("Crypt32.dll"));
	if (hCrypt32Module == NULL)
	{
		// Can't load Crypt32.dll - bail!
		FreeLibrary(hWinTrustModule);
		return ERROR_LOADLIBRARYFAILURE;
	}

	PWinVerifyTrust Func_WinVerifyTrust = (PWinVerifyTrust)GetProcAddress(hWinTrustModule, "WinVerifyTrust");
	if (Func_WinVerifyTrust == NULL) return ERROR_GETPROCADDRESSFAILURE;

	GUID GenericActionId = WINTRUST_ACTION_GENERIC_VERIFY_V2;
	WINTRUST_DATA WintrustData;
	WINTRUST_FILE_INFO FileInfo;

	crtless_memset(&WintrustData, 0, sizeof(WINTRUST_DATA));
	WintrustData.cbStruct = sizeof(WINTRUST_DATA);
	WintrustData.dwStateAction = WTD_STATEACTION_VERIFY;
	WintrustData.dwUIChoice = WTD_UI_NONE;
	WintrustData.fdwRevocationChecks = WTD_REVOKE_NONE;
	WintrustData.dwUnionChoice = WTD_CHOICE_FILE;

	crtless_memset(&FileInfo, 0, sizeof(WINTRUST_FILE_INFO));
	FileInfo.cbStruct = sizeof(WINTRUST_FILE_INFO);
#ifdef UNICODE
	FileInfo.pcwszFilePath = filePath;
#else
	// Must convert the input filePath to unicode
	LPWSTR pwstrFilePath = ansitowstr(filePath);
	FileInfo.pcwszFilePath = pwstrFilePath;
#endif
	WintrustData.pFile = &FileInfo;

	int verifyResult = -1;

	LONG trustResult = Func_WinVerifyTrust(NULL, &GenericActionId, &WintrustData);
	if (trustResult == 0)
	{
		// Verification succeeded - check additional details of the verified signature

		// NOTES:
		// VerifyStateDetails retrieves information about the "current" signature - i.e. 
		// the signature that WinVerifyTrust validated - using the WTHelper* APIs.
		//
		// This works with multiple signatures. If, for example, a file has two code signatures:
		//	1.) 1st signature - invalid / untrusted
		//	2.) 2nd signature - valid & trusted
		// A single call to WinVerifyTrust will return "true" (since one of the signatures - the 2nd - is valid)
		// and the WintrustData.hWVTStateData will refer to the 2nd (valid) signature.
		//
		// Thus, the following will validate additional details of the signature that WinVerifyTrust verified.

		int ret = VerifyStateDetails(hWinTrustModule, hCrypt32Module, WintrustData.hWVTStateData, certName, certIssuerName, microsoftRootCheck);
		if (ret != STATUS_OK)
		{
			// Additional verification failed
			verifyResult = ret;
		}
		else
		{
			// Additional verification succeeded
			verifyResult = STATUS_OK;
		}
	}
	else
	{
		// WinVerifyTrust returned a failure code
		verifyResult = ERROR_VERIFYTRUSTFAILURE;
	}

#ifndef UNICODE
	LocalFree(pwstrFilePath);
#endif

	FreeLibrary(hCrypt32Module);
	FreeLibrary(hWinTrustModule);

	return verifyResult;
}
