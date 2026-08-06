/*
 * Copyright 2021-2024 D'Arcy Smith.
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

#include "p101_identity/identity.h"
#include <p101_env/wrapper.h>

int p101_getgrgid_r(const struct p101_env *env, struct p101_error *err, gid_t gid, struct group *grp, char *buffer, size_t bufsize, struct group **result)
{
    int ret_val;

    P101_TRACE(env);
    P101_WRAPPER_FAULT_RETURN_CODE(env, err, ret_val);
    errno   = 0;
    ret_val = getgrgid_r(gid, grp, buffer, bufsize, result);

    if(ret_val != 0)
    {
        P101_ERROR_RAISE_ERRNO(err, ret_val);
    }

    P101_WRAPPER_DONE(env);
    return ret_val;
}

int p101_getgrnam_r(const struct p101_env *env, struct p101_error *err, const char *name, struct group *grp, char *buffer, size_t bufsize, struct group **result)
{
    int ret_val;

    P101_TRACE(env);
    P101_WRAPPER_FAULT_RETURN_CODE(env, err, ret_val);
    errno   = 0;
    ret_val = getgrnam_r(name, grp, buffer, bufsize, result);

    if(ret_val != 0)
    {
        P101_ERROR_RAISE_ERRNO(err, ret_val);
    }

    P101_WRAPPER_DONE(env);
    return ret_val;
}

/*
 * Copyright 2021-2024 D'Arcy Smith.
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

#include <pwd.h>

int p101_getpwnam_r(const struct p101_env *env, struct p101_error *err, const char *name, struct passwd *pwd, char *buffer, size_t bufsize, struct passwd **result)
{
    int ret_val;

    P101_TRACE(env);
    P101_WRAPPER_FAULT_RETURN_CODE(env, err, ret_val);
    errno   = 0;
    ret_val = getpwnam_r(name, pwd, buffer, bufsize, result);

    if(ret_val != 0)
    {
        P101_ERROR_RAISE_ERRNO(err, ret_val);
    }

    P101_WRAPPER_DONE(env);
    return ret_val;
}

int p101_getpwuid_r(const struct p101_env *env, struct p101_error *err, uid_t uid, struct passwd *pwd, char *buffer, size_t bufsize, struct passwd **result)
{
    int ret_val;

    P101_TRACE(env);
    P101_WRAPPER_FAULT_RETURN_CODE(env, err, ret_val);
    errno   = 0;
    ret_val = getpwuid_r(uid, pwd, buffer, bufsize, result);

    if(ret_val != 0)
    {
        P101_ERROR_RAISE_ERRNO(err, ret_val);
    }

    P101_WRAPPER_DONE(env);
    return ret_val;
}

/*
 * Copyright 2021-2024 D'Arcy Smith.
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

gid_t p101_getegid(const struct p101_env *env)
{
    gid_t ret_val;

    P101_TRACE(env);
    errno   = 0;
    ret_val = getegid();

    P101_TRACE_EXIT(env);
    return ret_val;
}

uid_t p101_geteuid(const struct p101_env *env)
{
    uid_t ret_val;

    P101_TRACE(env);
    errno   = 0;
    ret_val = geteuid();

    P101_TRACE_EXIT(env);
    return ret_val;
}

gid_t p101_getgid(const struct p101_env *env)
{
    gid_t ret_val;

    P101_TRACE(env);
    errno   = 0;
    ret_val = getgid();

    P101_TRACE_EXIT(env);
    return ret_val;
}

int p101_getgroups(const struct p101_env *env, struct p101_error *err, int gidsetsize, gid_t grouplist[])
{
    int ret_val;

    P101_TRACE(env);
    P101_WRAPPER_FAULT_RETURN(env, err, ret_val, -1);
    errno   = 0;
    ret_val = getgroups(gidsetsize, grouplist);

    if(ret_val == -1)
    {
        P101_ERROR_RAISE_ERRNO(err, errno);
    }

    P101_WRAPPER_DONE(env);
    return ret_val;
}

int p101_getlogin_r(const struct p101_env *env, struct p101_error *err, char *name, size_t namesize)
{
    int ret_val;

    P101_TRACE(env);
    P101_WRAPPER_FAULT_RETURN_CODE(env, err, ret_val);
    errno   = 0;
    ret_val = getlogin_r(name, namesize);

    if(ret_val != 0)
    {
        P101_ERROR_RAISE_ERRNO(err, ret_val);
    }

    P101_WRAPPER_DONE(env);
    return ret_val;
}

uid_t p101_getuid(const struct p101_env *env)
{
    uid_t ret_val;

    P101_TRACE(env);
    errno   = 0;
    ret_val = getuid();

    P101_TRACE_EXIT(env);
    return ret_val;
}

int p101_setegid(const struct p101_env *env, struct p101_error *err, gid_t gid)
{
    int ret_val;

    P101_TRACE(env);
    P101_WRAPPER_FAULT_RETURN(env, err, ret_val, -1);
    errno   = 0;
    ret_val = setegid(gid);

    if(ret_val == -1)
    {
        P101_ERROR_RAISE_ERRNO(err, errno);
    }

    P101_WRAPPER_DONE(env);
    return ret_val;
}

int p101_seteuid(const struct p101_env *env, struct p101_error *err, uid_t uid)
{
    int ret_val;

    P101_TRACE(env);
    P101_WRAPPER_FAULT_RETURN(env, err, ret_val, -1);
    errno   = 0;
    ret_val = seteuid(uid);

    if(ret_val == -1)
    {
        P101_ERROR_RAISE_ERRNO(err, errno);
    }

    P101_WRAPPER_DONE(env);
    return ret_val;
}

int p101_setgid(const struct p101_env *env, struct p101_error *err, gid_t gid)
{
    int ret_val;

    P101_TRACE(env);
    P101_WRAPPER_FAULT_RETURN(env, err, ret_val, -1);
    errno   = 0;
    ret_val = setgid(gid);

    if(ret_val == -1)
    {
        P101_ERROR_RAISE_ERRNO(err, errno);
    }

    P101_WRAPPER_DONE(env);
    return ret_val;
}

int p101_setuid(const struct p101_env *env, struct p101_error *err, uid_t uid)
{
    int ret_val;

    P101_TRACE(env);
    P101_WRAPPER_FAULT_RETURN(env, err, ret_val, -1);
    errno   = 0;
    ret_val = setuid(uid);

    if(ret_val == -1)
    {
        P101_ERROR_RAISE_ERRNO(err, errno);
    }

    P101_WRAPPER_DONE(env);
    return ret_val;
}

#ifdef __linux__
    #include <crypt.h>
#endif
#include <unistd.h>

char *p101_crypt(const struct p101_env *env, struct p101_error *err, const char *key, const char *salt)
{
    char *ret_val;

    P101_TRACE(env);
    P101_WRAPPER_FAULT_RETURN(env, err, ret_val, NULL);
    errno   = 0;
    ret_val = crypt(key, salt);    // cppcheck-suppress cryptCalled

    if(ret_val == NULL)
    {
        P101_ERROR_RAISE_ERRNO(err, (errno == 0) ? EIO : errno);
    }

    P101_WRAPPER_DONE(env);
    return ret_val;
}

int p101_setregid(const struct p101_env *env, struct p101_error *err, gid_t rgid, gid_t egid)
{
    int ret_val;

    P101_TRACE(env);
    P101_WRAPPER_FAULT_RETURN(env, err, ret_val, -1);
    errno   = 0;
    ret_val = setregid(rgid, egid);

    if(ret_val == -1)
    {
        P101_ERROR_RAISE_ERRNO(err, errno);
    }

    P101_WRAPPER_DONE(env);
    return ret_val;
}

int p101_setreuid(const struct p101_env *env, struct p101_error *err, uid_t ruid, uid_t euid)
{
    int ret_val;

    P101_TRACE(env);
    P101_WRAPPER_FAULT_RETURN(env, err, ret_val, -1);
    errno   = 0;
    ret_val = setreuid(ruid, euid);

    if(ret_val == -1)
    {
        P101_ERROR_RAISE_ERRNO(err, errno);
    }

    P101_WRAPPER_DONE(env);
    return ret_val;
}

#include <utmpx.h>

static int utmpx_error_code(void);

static int utmpx_error_code(void)
{
    int err_code;

    err_code = errno;

    if(err_code == 0)
    {
        err_code = EIO;
    }

    return err_code;
}

void p101_endutxent(const struct p101_env *env)
{
    P101_TRACE(env);
    errno = 0;
    endutxent();
    P101_TRACE_EXIT(env);
}

struct utmpx *p101_getutxent(const struct p101_env *env)
{
    struct utmpx *ret_val;

    P101_TRACE(env);
    errno   = 0;
    ret_val = getutxent();

    P101_TRACE_EXIT(env);
    return ret_val;
}

struct utmpx *p101_getutxid(const struct p101_env *env, const struct utmpx *id)
{
    struct utmpx *ret_val;

    P101_TRACE(env);
    errno   = 0;
    ret_val = getutxid(id);

    P101_TRACE_EXIT(env);
    return ret_val;
}

struct utmpx *p101_getutxline(const struct p101_env *env, const struct utmpx *line)
{
    struct utmpx *ret_val;

    P101_TRACE(env);
    errno   = 0;
    ret_val = getutxline(line);

    P101_TRACE_EXIT(env);
    return ret_val;
}

struct utmpx *p101_pututxline(const struct p101_env *env, struct p101_error *err, const struct utmpx *utmpx)
{
    struct utmpx *ret_val;

    P101_TRACE(env);
    P101_WRAPPER_FAULT_RETURN(env, err, ret_val, NULL);
    errno   = 0;
    ret_val = pututxline(utmpx);

    if(ret_val == NULL)
    {
        P101_ERROR_RAISE_ERRNO(err, utmpx_error_code());
    }

    P101_WRAPPER_DONE(env);
    return ret_val;
}

void p101_setutxent(const struct p101_env *env)
{
    P101_TRACE(env);
    errno = 0;
    setutxent();
    P101_TRACE_EXIT(env);
}

/*
 * Copyright 2022-2024 D'Arcy Smith.
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

#include <limits.h>

void p101_endusershell(const struct p101_env *env)
{
    P101_TRACE(env);
    endusershell();
    P101_TRACE_EXIT(env);
}

char *p101_getusershell(const struct p101_env *env)
{
    char *ret_val;

    P101_TRACE(env);
    ret_val = getusershell();

    P101_TRACE_EXIT(env);
    return ret_val;
}

void p101_setusershell(const struct p101_env *env)
{
    P101_TRACE(env);
    setusershell();
    P101_TRACE_EXIT(env);
}
