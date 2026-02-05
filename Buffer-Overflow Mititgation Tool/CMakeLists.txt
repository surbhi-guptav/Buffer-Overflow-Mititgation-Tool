cmake_minimum_required(VERSION 3.16)
project(BufferOverflowMitigationTool VERSION 2.0.0 LANGUAGES CXX)

# Set C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Build type
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

# Compiler flags
set(CMAKE_CXX_FLAGS_DEBUG "-g -O0 -DDEBUG -fsanitize=address -fsanitize=undefined -fsanitize=thread")
set(CMAKE_CXX_FLAGS_RELEASE "-O3 -DNDEBUG -fstack-protector-strong -fPIE -pie -D_FORTIFY_SOURCE=2")

# Platform-specific flags
if(WIN32)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /W4 /WX /GS /guard:cf /DYNAMICBASE /NXCOMPAT /HIGHENTROPYVA")
else()
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra -Werror -fstack-protector-strong -fPIE -pie")
endif()

# Find required packages
find_package(Threads REQUIRED)

# Include directories
include_directories(${CMAKE_CURRENT_SOURCE_DIR})

# Create directories
file(MAKE_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/logs)
file(MAKE_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/code_samples)

# Source files
set(SOURCES
    main.cpp
    static_analyzer.cpp
    dynamic_analyzer.cpp
    memory_tracker.cpp
    control_flow_guard.cpp
    runtime_protector.cpp
    code_patcher.cpp
    logger.cpp
)

# Header files
set(HEADERS
    analyzer/static_analyzer.h
    analyzer/dynamic_analyzer.h
    analyzer/memory_tracker.h
    analyzer/control_flow_guard.h
    runtime_protector.h
    code_patcher.h
    logger.h
    buffer_scanner.h
    shadow_stack.h
    boundary_checker.h
    canary_insertion.h
    exploit_prevention.h
    heap_guard.h
    memory_allocator.h
    signal_handler.h
    stack_protection.h
    config.h
)

# Create library
add_library(buffer_mitigation_lib STATIC ${SOURCES})
target_link_libraries(buffer_mitigation_lib Threads::Threads)

# Set library properties
set_target_properties(buffer_mitigation_lib PROPERTIES
    VERSION ${PROJECT_VERSION}
    SOVERSION ${PROJECT_VERSION_MAJOR}
    PUBLIC_HEADER "${HEADERS}"
)

# Create executable
add_executable(buffer_mitigation_tool main.cpp)
target_link_libraries(buffer_mitigation_tool buffer_mitigation_lib)

# Set executable properties
set_target_properties(buffer_mitigation_tool PROPERTIES
    OUTPUT_NAME "buffer-mitigation-tool"
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/bin
)

# Copy httplib if not found
if(NOT EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/httplib.h")
    file(DOWNLOAD
        "https://raw.githubusercontent.com/yhirose/cpp-httplib/master/httplib.h"
        "${CMAKE_CURRENT_SOURCE_DIR}/httplib.h"
        SHOW_PROGRESS
    )
endif()

# Add httplib
if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/httplib.h")
    target_include_directories(buffer_mitigation_tool PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
endif()

# Testing
enable_testing()
find_package(GTest QUIET)
if(GTest_FOUND)
    add_subdirectory(tests)
endif()

# Installation
install(TARGETS buffer_mitigation_tool buffer_mitigation_lib
    EXPORT BufferMitigationToolTargets
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib
    RUNTIME DESTINATION bin
    PUBLIC_HEADER DESTINATION include
)

# Install headers
install(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/
    DESTINATION include
    FILES_MATCHING PATTERN "*.h"
    PATTERN "CMakeLists.txt" EXCLUDE
    PATTERN "*.cpp" EXCLUDE
    PATTERN "*.txt" EXCLUDE
    PATTERN "*.md" EXCLUDE
)

# Export targets
install(EXPORT BufferMitigationToolTargets
    FILE BufferMitigationToolTargets.cmake
    NAMESPACE BufferMitigationTool::
    DESTINATION lib/cmake/BufferMitigationTool
)

# Create config file
include(CMakePackageConfigHelpers)
write_basic_package_version_file(
    BufferMitigationToolConfigVersion.cmake
    VERSION ${PROJECT_VERSION}
    COMPATIBILITY SameMajorVersion
)

configure_package_config_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/cmake/BufferMitigationToolConfig.cmake.in
    ${CMAKE_CURRENT_BINARY_DIR}/BufferMitigationToolConfig.cmake
    INSTALL_DESTINATION lib/cmake/BufferMitigationTool
)

install(FILES
    ${CMAKE_CURRENT_BINARY_DIR}/BufferMitigationToolConfig.cmake
    ${CMAKE_CURRENT_BINARY_DIR}/BufferMitigationToolConfigVersion.cmake
    DESTINATION lib/cmake/BufferMitigationTool
)

# Create pkg-config file
configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/cmake/buffer-mitigation-tool.pc.in
    ${CMAKE_CURRENT_BINARY_DIR}/buffer-mitigation-tool.pc
    @ONLY
)

install(FILES
    ${CMAKE_CURRENT_BINARY_DIR}/buffer-mitigation-tool.pc
    DESTINATION lib/pkgconfig
)

# Documentation
find_package(Doxygen QUIET)
if(DOXYGEN_FOUND)
    set(DOXYGEN_IN ${CMAKE_CURRENT_SOURCE_DIR}/docs/Doxyfile.in)
    set(DOXYGEN_OUT ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile)
    
    configure_file(${DOXYGEN_IN} ${DOXYGEN_OUT} @ONLY)
    
    add_custom_target(docs ALL
        COMMAND ${DOXYGEN_EXECUTABLE} ${DOXYGEN_OUT}
        WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
        COMMENT "Generating API documentation with Doxygen"
        VERBATIM
    )
    
    install(DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/html
        DESTINATION share/doc/buffer-mitigation-tool
    )
endif()

# Package
set(CPACK_PACKAGE_NAME "Buffer Overflow Mitigation Tool")
set(CPACK_PACKAGE_VERSION ${PROJECT_VERSION})
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "Advanced buffer overflow detection and mitigation tool")
set(CPACK_PACKAGE_VENDOR "Security Research Team")
set(CPACK_PACKAGE_CONTACT "security@example.com")

if(WIN32)
    set(CPACK_GENERATOR "NSIS;ZIP")
    set(CPACK_NSIS_DISPLAY_NAME "Buffer Overflow Mitigation Tool")
    set(CPACK_NSIS_PACKAGE_NAME "Buffer Overflow Mitigation Tool")
else()
    set(CPACK_GENERATOR "DEB;RPM;TGZ")
    set(CPACK_DEBIAN_PACKAGE_MAINTAINER "Security Research Team")
    set(CPACK_DEBIAN_PACKAGE_DEPENDS "libc6, libstdc++6")
    set(CPACK_RPM_PACKAGE_REQUIRES "glibc, libstdc++")
endif()

include(CPack)

# Print configuration summary
message(STATUS "Buffer Overflow Mitigation Tool Configuration:")
message(STATUS "  Version: ${PROJECT_VERSION}")
message(STATUS "  Build type: ${CMAKE_BUILD_TYPE}")
message(STATUS "  C++ standard: ${CMAKE_CXX_STANDARD}")
message(STATUS "  Install prefix: ${CMAKE_INSTALL_PREFIX}")
message(STATUS "  Tests enabled: ${BUILD_TESTING}")
message(STATUS "  Documentation: ${DOXYGEN_FOUND}")
