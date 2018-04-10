# NSIS FileCheck [![Build status](https://ci.appveyor.com/api/projects/status/4swfw5dvud34520r/branch/master?svg=true)](https://ci.appveyor.com/project/past-due/nsisfilecheck/branch/master)
[NSIS (Nullsoft Scriptable Install System)](https://en.wikipedia.org/wiki/Nullsoft_Scriptable_Install_System) plugin that enables:
- Calculating a file's hash (SHA1, SHA2)
- Verifying a file's Authenticode code signature (including details)
- Obtaining a file's string version info

### Supports:
- **Windows**: Windows XP -> Windows 10
- **NSIS**: 3.0+ (ANSI or Unicode)

### General Compatibility Notes:
The resulting `filecheck.dll`:
- Does **not** have a dependency on the CRT, and should run on systems that do not yet have the VCRedist / CRT installed.
- Dynamically loads all libraries except `kernel32.dll` and `user32.dll`, and handles differing OS / patch-level support of the underlying Windows APIs used automatically.

## Usage

_TODO: Usage examples coming soon._

## Development

### Compilation Requirements:
- Visual Studio 2017
- CMake 3.5+ (3.10+ recommended)

