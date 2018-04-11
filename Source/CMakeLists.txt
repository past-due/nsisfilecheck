cmake_minimum_required(VERSION 3.5)

if(NOT WIN32)
	message( FATAL_ERROR "Only supports Windows" )
endif()

if (MSVC)
	# Suppress all the standard libraries - the only ones needed are added later
	set(CMAKE_CXX_STANDARD_LIBRARIES "")
	set(CMAKE_C_STANDARD_LIBRARIES "")
endif()

set(CMAKE_CXX_STANDARD 11)

set(SOURCE_FILES filecheck.cpp codesigncheck.cpp nsis/pluginapi.c nsis/crt.cpp hashfile.cpp utils.cpp versioninfo.cpp)

# ANSI / MBCS DLL
add_library(filecheck_ansi MODULE ${SOURCE_FILES})
set_target_properties(filecheck_ansi PROPERTIES RUNTIME_OUTPUT_DIRECTORY_RELEASE "${CMAKE_CURRENT_BINARY_DIR}")
set_target_properties(filecheck_ansi PROPERTIES RUNTIME_OUTPUT_DIRECTORY_DEBUG "${CMAKE_CURRENT_BINARY_DIR}")
set_target_properties(filecheck_ansi PROPERTIES LIBRARY_OUTPUT_DIRECTORY_RELEASE "${CMAKE_CURRENT_BINARY_DIR}")
set_target_properties(filecheck_ansi PROPERTIES LIBRARY_OUTPUT_DIRECTORY_DEBUG "${CMAKE_CURRENT_BINARY_DIR}")
install(FILES "${CMAKE_CURRENT_BINARY_DIR}/filecheck_ansi.dll"
		RENAME "filecheck.dll"
		COMPONENT Plugins DESTINATION "Plugins/ansi")

# Unicode DLL
add_library(filecheck_unicode MODULE ${SOURCE_FILES})
target_compile_definitions(filecheck_unicode PRIVATE "UNICODE" "_UNICODE")
set_target_properties(filecheck_unicode PROPERTIES RUNTIME_OUTPUT_DIRECTORY_RELEASE "${CMAKE_CURRENT_BINARY_DIR}")
set_target_properties(filecheck_unicode PROPERTIES RUNTIME_OUTPUT_DIRECTORY_DEBUG "${CMAKE_CURRENT_BINARY_DIR}")
set_target_properties(filecheck_unicode PROPERTIES LIBRARY_OUTPUT_DIRECTORY_RELEASE "${CMAKE_CURRENT_BINARY_DIR}")
set_target_properties(filecheck_unicode PROPERTIES LIBRARY_OUTPUT_DIRECTORY_DEBUG "${CMAKE_CURRENT_BINARY_DIR}")
install(FILES "${CMAKE_CURRENT_BINARY_DIR}/filecheck_unicode.dll"
		RENAME "filecheck.dll"
		COMPONENT Plugins DESTINATION "Plugins/unicode")

if (MSVC)
	# Do not link the CRT (or any default libs)
	set_target_properties(filecheck_ansi filecheck_unicode PROPERTIES LINK_FLAGS "/NODEFAULTLIB /ENTRY:DllMain")
	# Do not use /GS (it requires the CRT)
	target_compile_options(filecheck_ansi PRIVATE "/GS-")
	target_compile_options(filecheck_unicode PRIVATE "/GS-")
	# *Do* explicitly link to kernel32.lib and user32.lib, which are required
	target_link_libraries(filecheck_ansi PRIVATE kernel32 user32)
	target_link_libraries(filecheck_unicode PRIVATE kernel32 user32)
endif()

###########################
# Additional Install Rules

# Copy the source files over into the "Source" folder
file(GLOB SRC_FILES "*.txt" "*.cpp" "*.c" "*.h")
INSTALL(FILES ${SRC_FILES}
		COMPONENT "Source" DESTINATION "Source")
INSTALL(DIRECTORY "nsis"
		COMPONENT "Source" DESTINATION "Source")
