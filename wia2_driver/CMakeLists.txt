cmake_minimum_required(VERSION 3.16)
project(MinoltaWia2Driver LANGUAGES C CXX)

if(WIN32)
    add_library(MinoltaWia2Driver SHARED
        MinoltaWia2Driver.cpp
        MinoltaWia2Driver.def
        ../scanner_tool/dimage_scan.c
    )
    target_compile_definitions(MinoltaWia2Driver PRIVATE DIMAGE_NO_MAIN _CRT_SECURE_NO_WARNINGS)
    target_link_libraries(MinoltaWia2Driver PRIVATE
        wiaservc
        sti
        ole32
        oleaut32
        uuid
        advapi32
    )
endif()
