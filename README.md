# NSIS FileCheck [![Build status](https://ci.appveyor.com/api/projects/status/4swfw5dvud34520r/branch/master?svg=true)](https://ci.appveyor.com/project/past-due/nsisfilecheck/branch/master) [![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT) [![NSIS: 3.0+](https://img.shields.io/badge/NSIS-3.0%2B-orange.svg)](https://en.wikipedia.org/wiki/Nullsoft_Scriptable_Install_System)
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

## Security Tips

#### Avoid SHA-1 if possible

> [Since 2005 SHA-1 has not been considered secure against well-funded opponents, and since 2010 many organizations have recommended its replacement by SHA-2 or SHA-3.](https://en.wikipedia.org/wiki/SHA-1)

This plugin supports SHA-2 on Windows XP SP3 and above. For almost all cases, there is zero reason to use SHA-1.

#### Avoid TOCTOU

[Time of check to time of use (TOCTOU / TOCTTOU)](https://en.wikipedia.org/wiki/Time_of_check_to_time_of_use) bugs can lead to security vulnerabilities.

Do not assume that a file that has been checked has not been modified between the time of the check and the time of the use. Use proper security permissions on any containing / temporary folders to ensure that nothing unprivileged can modify a file between a check and any use.

## Development

### Compilation Requirements:
- Visual Studio 2017
- CMake 3.5+ (3.10+ recommended)
