cmake_minimum_required(VERSION 3.10)
project(NIDS_Sensor VERSION 1.0 LANGUAGES CXX)

# --- User-configurable hints ---
if(NOT DEFINED NPCAP_SDK_ROOT)
    set(NPCAP_SDK_ROOT "C:/npcap-sdk" CACHE PATH "Path to Npcap/WinPcap SDK root (optional)")
endif()

# --- Compiler settings ---
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# --- Source/header files ---
set(SRC_FILES
    src/main.cpp
    src/packet_sniffer.cpp
)
set(HEADER_FILES
    src/packet_sniffer.h
)

add_executable(nids_sensor ${SRC_FILES} ${HEADER_FILES})

# --- Find libpcap / wpcap ---
find_package(Pcap QUIET)

if(Pcap_FOUND)
    message(STATUS "Found Pcap via find_package: ${Pcap_VERSION}")
    target_include_directories(nids_sensor PRIVATE ${Pcap_INCLUDE_DIRS})
    target_link_libraries(nids_sensor PRIVATE ${Pcap_LIBRARIES})
else()
    message(STATUS "find_package(Pcap) did not locate a library. Attempting manual discovery...")

    find_path(PCAP_INCLUDE_DIR pcap.h
        HINTS
            ${NPCAP_SDK_ROOT}/Include
            /usr/include
            /usr/include/pcap
    )

    if(WIN32)
        find_library(WPCAP_LIB wpcap HINTS ${NPCAP_SDK_ROOT}/Lib PATHS ${NPCAP_SDK_ROOT}/Lib)
        find_library(PACKET_LIB Packet HINTS ${NPCAP_SDK_ROOT}/Lib PATHS ${NPCAP_SDK_ROOT}/Lib)
        if(NOT WPCAP_LIB)
            message(FATAL_ERROR "wpcap library not found. Install Npcap/WinPcap or set NPCAP_SDK_ROOT.")
        endif()
        target_include_directories(nids_sensor PRIVATE ${PCAP_INCLUDE_DIR})
        target_link_libraries(nids_sensor PRIVATE ${WPCAP_LIB} ${PACKET_LIB})
    else()
        find_library(PCAP_LIB pcap)
        if(NOT PCAP_LIB)
            message(FATAL_ERROR "libpcap not found (pcap). Install libpcap-dev or set PCAP paths.")
        endif()
        target_include_directories(nids_sensor PRIVATE ${PCAP_INCLUDE_DIR})
        target_link_libraries(nids_sensor PRIVATE ${PCAP_LIB})
    endif()
endif()

# --- Link Winsock on Windows ---
if(WIN32)
    find_library(WS2_LIB ws2_32)
    if(WS2_LIB)
        target_link_libraries(nids_sensor PRIVATE ${WS2_LIB})
    endif()
endif()

# --- Add include directory for local headers ---
target_include_directories(nids_sensor PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)

# --- Useful options ---
option(VERBOSE_BUILD "Enable verbose build output" OFF)
if(VERBOSE_BUILD)
    set(CMAKE_VERBOSE_MAKEFILE ON)
endif()

# --- Installation (optional) ---
install(TARGETS nids_sensor RUNTIME DESTINATION bin)
install(FILES src/packet_sniffer.h DESTINATION include)

message(STATUS "Configuration complete. Build with: cmake --build .")
