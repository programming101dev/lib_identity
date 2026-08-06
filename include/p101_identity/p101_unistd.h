#ifndef LIBP101_IDENTITY_P101_UNISTD_H
#define LIBP101_IDENTITY_P101_UNISTD_H

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

    char *p101_crypt(const struct p101_env *env, struct p101_error *err, const char *key, const char *salt);
    void  p101_endusershell(const struct p101_env *env);
    gid_t p101_getegid(const struct p101_env *env);
    uid_t p101_geteuid(const struct p101_env *env);
    gid_t p101_getgid(const struct p101_env *env);
    int   p101_getgroups(const struct p101_env *env, struct p101_error *err, int gidsetsize, gid_t grouplist[]);
    int   p101_getlogin_r(const struct p101_env *env, struct p101_error *err, char *name, size_t namesize);
    uid_t p101_getuid(const struct p101_env *env);
    char *p101_getusershell(const struct p101_env *env);
    int   p101_setegid(const struct p101_env *env, struct p101_error *err, gid_t gid);
    int   p101_seteuid(const struct p101_env *env, struct p101_error *err, uid_t uid);
    int   p101_setgid(const struct p101_env *env, struct p101_error *err, gid_t gid);
    int   p101_setregid(const struct p101_env *env, struct p101_error *err, gid_t rgid, gid_t egid);
    int   p101_setreuid(const struct p101_env *env, struct p101_error *err, uid_t ruid, uid_t euid);
    int   p101_setuid(const struct p101_env *env, struct p101_error *err, uid_t uid);
    void  p101_setusershell(const struct p101_env *env);

#ifdef __cplusplus
}
#endif

#endif    // LIBP101_IDENTITY_P101_UNISTD_H
