#ifndef LIBP101_IDENTITY_P101_GRP_H
#define LIBP101_IDENTITY_P101_GRP_H

/*
 * Copyright 2026 D'Arcy Smith.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef LIBP101_IDENTITY_SHARED_DECLARATIONS
    #define LIBP101_IDENTITY_SHARED_DECLARATIONS
    #include <grp.h>
    #include <p101_env/env.h>
    #include <p101_error/attributes.h>
    #include <pwd.h>
    #include <stddef.h>
    #include <sys/types.h>
    #include <unistd.h>
#endif    // LIBP101_IDENTITY_SHARED_DECLARATIONS

#ifdef __cplusplus
extern "C"
{
#endif

    int p101_getgrgid_r(const struct p101_env *env, struct p101_error *err, gid_t gid, struct group *grp, char *buffer, size_t bufsize, struct group **result);
    int p101_getgrnam_r(const struct p101_env *env, struct p101_error *err, const char *name, struct group *grp, char *buffer, size_t bufsize, struct group **result);

#ifdef __cplusplus
}
#endif

#endif    // LIBP101_IDENTITY_P101_GRP_H
