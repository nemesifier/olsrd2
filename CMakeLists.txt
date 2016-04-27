project (OONF C)
cmake_minimum_required(VERSION 2.8.12 FATAL_ERROR)

########################################################
#### Set a default build type if none was specified ####
########################################################

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  message(STATUS "Setting build type to 'Debug' as none was specified.")
  set(CMAKE_BUILD_TYPE Debug CACHE STRING "Choose the type of build." FORCE)
  # Set the possible values of build type for cmake-gui
  set_property(CACHE CMAKE_BUILD_TYPE PROPERTY STRINGS "Debug" "Release"
    "MinSizeRel" "RelWithDebInfo")
endif()

###########################
#### API configuration ####
###########################

# set cached variables
include (./cmake/lib_config.cmake)

# include compiler flags
include (./cmake/cc_flags.cmake)

########################################
#### get repository tag and version ####
########################################

include (cmake/get_version.cmake)
IF(EXISTS "${PROJECT_BINARY_DIR}/version.cmake")
  include (${PROJECT_BINARY_DIR}/version.cmake)
ENDIF()

########################
#### Doxygen target ####
########################

find_package(Doxygen)
if(DOXYGEN_FOUND)
    configure_file(${CMAKE_CURRENT_SOURCE_DIR}/cmake/files/framework.doxyfile.in
        ${CMAKE_CURRENT_BINARY_DIR}/framework.doxyfile @ONLY)
    add_custom_target(doc
        ${DOXYGEN_EXECUTABLE} ${CMAKE_CURRENT_BINARY_DIR}/framework.doxyfile
        WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}
        COMMENT "Generating API documentation with Doxygen" VERBATIM
    )
endif(DOXYGEN_FOUND)

#############################
#### add tarball targets ####
#############################

ADD_CUSTOM_TARGET(targz  COMMAND ${CMAKE_COMMAND}
                                 -D SOURCE:STRING=${CMAKE_SOURCE_DIR}
                                 -D BINARY:STRING=${PROJECT_BINARY_DIR}
                                 -D VERSION:STRING=${VERSION}
                                 -D FORMAT:STRING=tar.gz
                                 -D TARBALL:STRING=${TARBALL}
                                 -D TARPREFIX:STRING=${TARPREFIX}
                                 -P ${CMAKE_SOURCE_DIR}/cmake/generate_archive.cmake)
                                
ADD_CUSTOM_TARGET(tarbz2 COMMAND ${CMAKE_COMMAND}
                                 -D SOURCE:STRING=${CMAKE_SOURCE_DIR}
                                 -D BINARY:STRING=${PROJECT_BINARY_DIR}
                                 -D VERSION:STRING=${VERSION}
                                 -D FORMAT:STRING=tar.bz2
                                 -D TARBALL:STRING=${TARBALL}
                                 -D TARPREFIX:STRING=${TARPREFIX}
                                 -P ${CMAKE_SOURCE_DIR}/cmake/generate_archive.cmake)
ADD_CUSTOM_TARGET(zip    COMMAND ${CMAKE_COMMAND}
                                 -D SOURCE:STRING=${CMAKE_SOURCE_DIR}
                                 -D BINARY:STRING=${PROJECT_BINARY_DIR}
                                 -D VERSION:STRING=${VERSION}
                                 -D FORMAT:STRING=zip
                                 -D TARBALL:STRING=${TARBALL}
                                 -D TARPREFIX:STRING=${TARPREFIX}
                                 -P ${CMAKE_SOURCE_DIR}/cmake/generate_archive.cmake)

#########################
#### Compile targets ####
#########################

# add define for length of base path
string(LENGTH "${CMAKE_SOURCE_DIR}/" BASELENGTH)
add_definitions(-DBASEPATH_LENGTH=${BASELENGTH})

# include build helper
include (cmake/declare_library.cmake)

# include files
include_directories(${PROJECT_BINARY_DIR})
include_directories(src-api)

if (NOT OONF_NO_TESTING)
    ENABLE_TESTING()
endif (NOT OONF_NO_TESTING)

# define static and dynamic target
add_custom_target(static)
add_custom_target(dynamic)

# start compiling core and plugins
add_subdirectory(src-api)
add_subdirectory(src-plugins)
# add_subdirectory(examples)
add_subdirectory(src)

if (NOT OONF_NO_TESTING)
    add_subdirectory(tests)
endif (NOT OONF_NO_TESTING)
