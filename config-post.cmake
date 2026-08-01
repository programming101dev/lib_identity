# Platform values are reliable only after CMake's project() call.
if(CMAKE_SYSTEM_NAME STREQUAL "Linux" OR CMAKE_SYSTEM_NAME STREQUAL "FreeBSD")
    list(APPEND p101_identity_LINK_LIBRARIES crypt)
endif ()
