# Project metadata
set(PROJECT_NAME "p101_identity")
set(PROJECT_VERSION "0.0.1")
set(PROJECT_DESCRIPTION "Users, groups, credentials, login records, and user shells")
set(PROJECT_LANGUAGE "C")

set(CMAKE_C_STANDARD 17)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

set(STANDARD_FLAGS
        -D_POSIX_C_SOURCE=200809L
        -D_XOPEN_SOURCE=700
        -Werror
)
set(DARWIN_STANDARD_FLAGS -D_DARWIN_C_SOURCE)
set(LINUX_STANDARD_FLAGS -D_GNU_SOURCE)
set(BSD_STANDARD_FLAGS -D_BSD_SOURCE -D__BSD_VISIBLE)

set(LIBRARY_TARGETS p101_identity)
set(p101_identity_SOURCES
        src/grp.c
        src/pwd.c
        src/unistd.c
        src/utmpx.c
)
set(p101_identity_HEADERS
        include/p101_identity/p101_grp.h
        include/p101_identity/p101_pwd.h
        include/p101_identity/p101_unistd.h
        include/p101_identity/p101_utmpx.h
)
set(p101_identity_LINK_LIBRARIES
        p101_error
        p101_env
        p101_c
)
