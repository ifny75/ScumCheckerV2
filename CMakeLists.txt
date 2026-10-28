cmake_minimum_required(VERSION 3.24)
project(ScumCheckerV2 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if (NOT WIN32)
    message(FATAL_ERROR "ScumCheckerV2 is a Windows/WebView2 application.")
endif()

set(WEBVIEW2_ROOT "${CMAKE_SOURCE_DIR}/third_party/webview2" CACHE PATH "Path to extracted Microsoft.Web.WebView2 NuGet package")
set(WEBVIEW2_INCLUDE_DIR "${WEBVIEW2_ROOT}/build/native/include")

if (CMAKE_SIZEOF_VOID_P EQUAL 8)
    set(WEBVIEW2_ARCH "x64")
else()
    set(WEBVIEW2_ARCH "x86")
endif()

set(WEBVIEW2_LOADER_LIB "${WEBVIEW2_ROOT}/build/native/${WEBVIEW2_ARCH}/WebView2LoaderStatic.lib")

if (NOT EXISTS "${WEBVIEW2_INCLUDE_DIR}/WebView2.h" OR NOT EXISTS "${WEBVIEW2_LOADER_LIB}")
    message(FATAL_ERROR "WebView2 SDK was not found. Run scripts/fetch_webview2.ps1 first, then re-run CMake.")
endif()

add_library(scum_scanner STATIC
    scanner/NativeScannerApi.cpp
    scanner/NativeScannerApi.h
    scanner/ScannerShared.cpp
    scanner/ScannerShared.h
    scanner/FileScanner.cpp
    scanner/FileScanner.h
    scanner/ProcessScanner.cpp
    scanner/ProcessScanner.h
    scanner/ProcessModuleEnumerator.h
    scanner/DriverScanner.cpp
    scanner/DriverScanner.h
    scanner/RegistryScanner.cpp
    scanner/RegistryScanner.h
    scanner/SteamScanner.cpp
    scanner/SteamScanner.h
    scanner/PcieScanner.cpp
    scanner/PcieScanner.h
    scanner/HypervisorScanner.cpp
    scanner/HypervisorScanner.h
    scanner/KernelSysScanner.cpp
    scanner/KernelSysScanner.h
    scanner/SecurityConfigScanner.cpp
    scanner/SecurityConfigScanner.h
    scanner/DmaNetworkInspector.cpp
    scanner/DmaNetworkInspector.h
    scanner/SystemHistoryInspector.cpp
    scanner/SystemHistoryInspector.h
    scanner/RiskAnalyzer.cpp
    scanner/RiskAnalyzer.h
    scanner/ScanReporting.h
    scanner/ScanRunner.h
)

target_compile_definitions(scum_scanner PRIVATE
    UNICODE
    _UNICODE
    WIN32_LEAN_AND_MEAN
)
target_compile_options(scum_scanner PRIVATE /EHsc /utf-8)
target_link_libraries(scum_scanner PRIVATE advapi32 psapi wintrust shlwapi bcrypt crypt32 setupapi iphlpapi ws2_32)

include(CTest)
if (BUILD_TESTING)
    add_executable(scanner_regression_tests tests/ScannerRegressionTests.cpp)
    target_include_directories(scanner_regression_tests PRIVATE scanner)
    target_compile_definitions(scanner_regression_tests PRIVATE UNICODE _UNICODE WIN32_LEAN_AND_MEAN)
    target_compile_options(scanner_regression_tests PRIVATE /EHsc /utf-8)
    target_link_libraries(scanner_regression_tests PRIVATE scum_scanner)
    add_test(NAME scanner_regressions COMMAND scanner_regression_tests)
    find_program(NODE_EXECUTABLE node)
    if (NODE_EXECUTABLE)
        add_test(NAME scan_report_regressions COMMAND "${NODE_EXECUTABLE}" "${CMAKE_SOURCE_DIR}/tests/ScanReportTests.cjs")
    endif()
endif()

# --- Embed the web UI (html/css/js/svg/png/...) into the executable ------------
set(WEB_DIR "${CMAKE_SOURCE_DIR}/web")
set(GEN_DIR "${CMAKE_BINARY_DIR}/generated")
set(GEN_WEB_RC  "${GEN_DIR}/web_resources.rc")
set(GEN_WEB_CPP "${GEN_DIR}/web_manifest.cpp")
set(GEN_WEB_H   "${GEN_DIR}/web_manifest.h")

file(MAKE_DIRECTORY "${GEN_DIR}")
file(GLOB_RECURSE WEB_FILES CONFIGURE_DEPENDS "${WEB_DIR}/*")

add_custom_command(
    OUTPUT "${GEN_WEB_RC}" "${GEN_WEB_CPP}" "${GEN_WEB_H}"
    COMMAND ${CMAKE_COMMAND}
            -DWEB_DIR=${WEB_DIR}
            -DOUT_RC=${GEN_WEB_RC}
            -DOUT_CPP=${GEN_WEB_CPP}
            -DOUT_H=${GEN_WEB_H}
            -P "${CMAKE_SOURCE_DIR}/tools/embed_web.cmake"
    DEPENDS ${WEB_FILES} "${CMAKE_SOURCE_DIR}/tools/embed_web.cmake"
    COMMENT "Embedding web assets into ScumCheckerV2"
    VERBATIM
)

add_executable(ScumCheckerV2 WIN32
    app/main.cpp
    app/resources.rc
    "${GEN_WEB_RC}"
    "${GEN_WEB_CPP}"
)

set_property(DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}" PROPERTY VS_STARTUP_PROJECT ScumCheckerV2)

target_compile_definitions(ScumCheckerV2 PRIVATE
    UNICODE
    _UNICODE
    WIN32_LEAN_AND_MEAN
)
target_compile_options(ScumCheckerV2 PRIVATE /EHsc /utf-8)
target_include_directories(ScumCheckerV2 PRIVATE "${WEBVIEW2_INCLUDE_DIR}" scanner "${GEN_DIR}")
target_link_libraries(ScumCheckerV2 PRIVATE
    scum_scanner
    "${WEBVIEW2_LOADER_LIB}"
    user32
    ole32
    shell32
    shlwapi
)

# Web assets and the icon are embedded inside the .exe (see embed_web.cmake and
# resources.rc), so they are no longer copied next to the binary. profiles/ holds
# editable scan rules and programms/ holds standalone third-party tools, so those
# stay on disk.
add_custom_command(TARGET ScumCheckerV2 POST_BUILD
    COMMAND ${CMAKE_COMMAND}
            -DSRC_DIR=${CMAKE_SOURCE_DIR}/profiles
            -DDST_DIR=$<TARGET_FILE_DIR:ScumCheckerV2>/profiles
            -P "${CMAKE_SOURCE_DIR}/tools/copy_runtime_dir.cmake"
    COMMAND ${CMAKE_COMMAND}
            -DSRC_DIR=${CMAKE_SOURCE_DIR}/programms
            -DDST_DIR=$<TARGET_FILE_DIR:ScumCheckerV2>/programms
            -P "${CMAKE_SOURCE_DIR}/tools/copy_runtime_dir.cmake"
    VERBATIM
)
