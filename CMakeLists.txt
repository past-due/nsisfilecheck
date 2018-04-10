cmake_minimum_required(VERSION 3.5)
project(filecheck)

if(NOT WIN32)
	message( FATAL_ERROR "Only supports Windows" )
endif()

add_subdirectory(Source)
