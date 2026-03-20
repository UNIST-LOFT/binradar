cmake_minimum_required(VERSION 3.7)

project(Solver)

# fuzzy-sat
add_subdirectory(fuzzy-sat)
add_subdirectory(libsbsv)

add_executable(solver-smt main.c i386.c branch_coverage.c opts.c xxHash/xxhash.c)
add_executable(solver-fuzzy main.c i386.c branch_coverage.c opts.c xxHash/xxhash.c)

target_compile_definitions(solver-smt PRIVATE USE_FUZZY_SOLVER=0)
target_compile_definitions(solver-fuzzy PRIVATE USE_FUZZY_SOLVER=1)

# Link against the modified Z3 built by fuzzolic-z3 (target name is libz3)
# and the fuzzy-sat library target (Z3Fuzzy_static) created by fuzzy-sat/lib.
# Ensure order: Z3Fuzzy_static may depend on libz3.
target_link_libraries(solver-smt PRIVATE libz3 Z3Fuzzy_static sbsv)
target_link_libraries(solver-fuzzy PRIVATE libz3 Z3Fuzzy_static sbsv)

# If you still want to link system z3 instead, remove libz3 above and use z3.
# But here we want the modified internal Z3, so link the lib built from fuzzolic-z3.

# glib
find_package(PkgConfig REQUIRED)
pkg_search_module(GLIB REQUIRED glib-2.0)
target_include_directories(solver-smt PRIVATE ${GLIB_INCLUDE_DIRS})
target_include_directories(solver-fuzzy PRIVATE ${GLIB_INCLUDE_DIRS})
target_link_libraries(solver-smt PRIVATE ${GLIB_LDFLAGS})
target_link_libraries(solver-fuzzy PRIVATE ${GLIB_LDFLAGS})

set(CMAKE_CXX_FLAGS "-Wall -Wextra -O3 -g")
set(CMAKE_C_FLAGS "-O3 -g")
#set(CMAKE_CXX_FLAGS_DEBUG "-g")
#set(CMAKE_CXX_FLAGS_RELEASE "-O3")
