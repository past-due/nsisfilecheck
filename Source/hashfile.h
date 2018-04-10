#pragma once
#ifndef ___HASH_FILE__H___
#define ___HASH_FILE__H___

#include <Windows.h>

enum HASH_ALGORITHM {
	HASH_SHA1,
	HASH_SHA256,
	HASH_SHA384,
	HASH_SHA512
};

#ifdef __cplusplus 
extern "C" {
#endif

// Calculates the hash of a file
// If successful, a pointer to the newly-(heap)-allocated hash string is stored in hash_out.
// The caller is responsible for freeing the hash string by calling HeapFree(GetProcessHeap(), 0, hash_out).
// Returns: 0 if successful, non-0 if failed
int HashFile(LPCTSTR pFilename, HASH_ALGORITHM algorithm, LPTSTR &hash_out);

#ifdef __cplusplus
}
#endif

#endif//!___HASH_FILE__H___
