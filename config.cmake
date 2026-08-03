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
        src/posix/grp.c
        src/posix/pwd.c
        src/posix/unistd.c
        src/posix_xsi/unistd.c
        src/posix_xsi/utmpx.c
        src/unix/unistd.c
)
set(p101_identity_HEADERS
        include/p101_identity/identity.h
)
set(p101_identity_LINK_LIBRARIES
        p101_error
        p101_env
        p101_c
)
