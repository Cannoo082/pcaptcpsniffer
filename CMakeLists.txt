cmake_minimum_required(VERSION 3.7)
project(pcaptcpsniffer)

set(CMAKE_CXX_STANDARD 17)

include(FindPCAP.cmake)

add_executable(pcaptcpsniffer
        interface.cpp)


find_package(PkgConfig REQUIRED)
pkg_check_modules(Xlsxwriter REQUIRED IMPORTED_TARGET xlsxwriter)
target_link_libraries(pcaptcpsniffer PUBLIC PkgConfig::Xlsxwriter ${PCAP_LIBRARY})









