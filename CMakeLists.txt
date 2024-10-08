# Root CMake file for NDN-Lite over POSIX
cmake_minimum_required (VERSION 3.5)
project(ndn-lite-exp)

option(BUILD_DOCS "Build documentation" OFF)
option(DYNAMIC_LIB "Build dynamic link library" on)
option(BUILD_PYTHON "Build python bindings" OFF)

if (NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE DEBUG)
endif()

add_definitions(-D_GNU_SOURCE)
set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=c11 -Werror -Wno-format -Wno-int-to-void-pointer-cast -Wno-int-to-pointer-cast")
# set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=c11 -Wno-format -Wno-int-to-pointer-cast -Wunused-parameter -Wunused-variable") #unit test
set(CMAKE_C_FLAGS_DEBUG "-O0 -ggdb")
set(CMAKE_C_FLAGS_RELEASE "-O3")

set(DIR_CMAKEFILES "${PROJECT_SOURCE_DIR}/CMakeInputs")
set(DIR_NDN_LITE "${PROJECT_SOURCE_DIR}/ndn-lite")
set(DIR_ADAPTATION "${PROJECT_SOURCE_DIR}/adaptation")
set(DIR_EXAMPLES "${PROJECT_SOURCE_DIR}/examples")
include_directories(${PROJECT_SOURCE_DIR})

# NDN-Lite static library
if(DYNAMIC_LIB)
  add_library(ndn-lite SHARED)
else()
  add_library(ndn-lite STATIC)
endif()
include(${DIR_CMAKEFILES}/ndnlite.cmake)

# SWIG library
if(BUILD_PYTHON)
  find_package(SWIG 3.0)
  find_package (Python3 COMPONENTS Interpreter Development)
  include(${SWIG_USE_FILE})
  cmake_policy(SET CMP0078 NEW)
  cmake_policy(SET CMP0086 NEW)
  include(UseSWIG)

  set (UseSWIG_TARGET_NAME_PREFERENCE STANDARD)
  set(PYTHON_WRAPPER "${PROJECT_SOURCE_DIR}/wrapper/ndnlite-wrapper.i")
  set_property(
    SOURCE "${PYTHON_WRAPPER}" PROPERTY
    GENERATED_INCLUDE_DIRECTORIES "${Python3_INCLUDE_DIRS}"
  )
  set_property(
    SOURCE "${PYTHON_WRAPPER}" PROPERTY
    CPLUSPLUS ON
  )
  swig_add_library(pyndnlite
    TYPE SHARED
    LANGUAGE python
    OUTPUT_DIR "${PROJECT_BINARY_DIR}/pyndnlite"
    OUTFILE_DIR "${PROJECT_BINARY_DIR}/pyndnlite-tmp"
    SOURCES "${PYTHON_WRAPPER}"
  )
  set_target_properties(pyndnlite PROPERTIES
    SUFFIX ".so"
    LIBRARY_OUTPUT_DIRECTORY "${PROJECT_BINARY_DIR}/pyndnlite"
    ARCHIVE_OUTPUT_DIRECTORY "${PROJECT_BINARY_DIR}/pyndnlite"
    RUNTIME_OUTPUT_DIRECTORY "${PROJECT_BINARY_DIR}/pyndnlite"
  )
  target_link_libraries(pyndnlite
    ndn-lite
    ${Python3_LIBRARIES}
  )
  unset(PYTHON_WRAPPER)
endif()

# Adaptation
include(${DIR_CMAKEFILES}/adaptation.cmake)

# Examples
include(${DIR_CMAKEFILES}/examples.cmake)

# Doxygen
find_package(Doxygen
  OPTIONAL_COMPONENTS dot
)
if (DOXYGEN_FOUND AND BUILD_DOCS)
  set(DOXYGEN_PROJECT_LOGO ${PROJECT_SOURCE_DIR}/docs/logo.jpeg)
  set(DOXYGEN_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR}/docs)
  set(DOXYGEN_TAB_SIZE 2)
  set(DOXYGEN_OPTIMIZE_OUTPUT_FOR_C YES)
  set(DOXYGEN_EXTRACT_ALL YES)
  set(DOXYGEN_EXTRACT_STATIC YES)
  set(DOXYGEN_INCLUDE_GRAPH NO)
  set(DOXYGEN_INCLUDED_BY_GRAPH NO)
  set(DOXYGEN_UML_LOOK YES)
  set(DOXYGEN_UML_LIMIT_NUM_FIELDS 3)
  set(DOXYGEN_JAVADOC_AUTOBRIEF YES)
  set(DOXYGEN_USE_MDFILE_AS_MAINPAGE ${PROJECT_SOURCE_DIR}/ndn-lite/README.md)
  doxygen_add_docs(docs
    ${PROJECT_SOURCE_DIR}/docs
    ${PROJECT_SOURCE_DIR}/ndn-lite
    COMMENT "Generating API documentation with Doxygen"
  )
else ()
  message("Documentation skipped")
endif ()
#testprogram
#add_executable(${DIR_EXAMPLES}/udp-basic-producer.c);
#target_link_libraries(unittest ndn-lite-ex)

# Unit test program
add_executable(producer ${DIR_EXAMPLES}/udp-basic-producer.c)
target_link_libraries(producer ndn-lite)
add_executable(consumer ${DIR_EXAMPLES}/udp-basic-consumer.c)
target_link_libraries(consumer ndn-lite)
add_executable(group_producer ${DIR_EXAMPLES}/udp-group-producer.c)
target_link_libraries(group_producer ndn-lite)
add_executable(group_consumer ${DIR_EXAMPLES}/udp-group-consumer.c)
target_link_libraries(group_consumer ndn-lite)
add_executable(nfd-basic-consumer ${DIR_EXAMPLES}/nfd-basic-consumer.c)
target_link_libraries(nfd-basic-consumer ndn-lite)
add_executable(nfd-basic-producer ${DIR_EXAMPLES}/nfd-basic-producer.c)
target_link_libraries(nfd-basic-producer ndn-lite)
add_executable(f_p ${DIR_EXAMPLES}/file-transfer-server.c)
target_link_libraries(f_p ndn-lite)
add_executable(f_c ${DIR_EXAMPLES}/file-transfer-client.c)
target_link_libraries(f_c ndn-lite)
#include(${DIR_CMAKEFILES}/unittest.cmake)

# Copy headers
include(GNUInstallDirs)
install(DIRECTORY "${PROJECT_SOURCE_DIR}/ndn-lite"
        DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}"
        FILES_MATCHING
        PATTERN "*.h"
)
install(DIRECTORY "${PROJECT_SOURCE_DIR}/adaptation"
        DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}"
        FILES_MATCHING
        PATTERN "*.h"
)
install(FILES "${PROJECT_SOURCE_DIR}/ndn-lite.h"
        DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}"
)
install(DIRECTORY "${PROJECT_SOURCE_DIR}/ndn-lite"
        DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}"
        FILES_MATCHING
        PATTERN "*.h"
)
#install(FILES "${PROJECT_SOURCE_DIR}/ndn-lite/util/dll.h"
#        DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}"
#)
install(TARGETS ndn-lite
        ARCHIVE DESTINATION "${CMAKE_INSTALL_LIBDIR}"
        LIBRARY DESTINATION "${CMAKE_INSTALL_LIBDIR}"
)