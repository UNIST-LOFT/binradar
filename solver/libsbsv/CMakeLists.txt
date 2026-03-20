cmake_minimum_required(VERSION 3.16)
project(sbsv VERSION 0.1.0 LANGUAGES C)

include(GNUInstallDirs)
include(CMakePackageConfigHelpers)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

add_library(sbsv STATIC
    src/sbsv.c
    src/sbsv_parser.c
)

add_library(sbsv::sbsv ALIAS sbsv)

target_include_directories(sbsv
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
)

add_executable(sbsv_tests
    tests/test_main.c
)

target_link_libraries(sbsv_tests PRIVATE sbsv)

install(
    TARGETS sbsv
    EXPORT sbsvTargets
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)

install(
    DIRECTORY include/
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
)

install(
    EXPORT sbsvTargets
    FILE sbsvTargets.cmake
    NAMESPACE sbsv::
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/sbsv
)

write_basic_package_version_file(
    ${CMAKE_CURRENT_BINARY_DIR}/sbsvConfigVersion.cmake
    VERSION ${PROJECT_VERSION}
    COMPATIBILITY SameMajorVersion
)

configure_package_config_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/cmake/sbsvConfig.cmake.in
    ${CMAKE_CURRENT_BINARY_DIR}/sbsvConfig.cmake
    INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/sbsv
)

install(
    FILES
        ${CMAKE_CURRENT_BINARY_DIR}/sbsvConfig.cmake
        ${CMAKE_CURRENT_BINARY_DIR}/sbsvConfigVersion.cmake
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/sbsv
)

enable_testing()
add_test(NAME sbsv_tests COMMAND sbsv_tests)
