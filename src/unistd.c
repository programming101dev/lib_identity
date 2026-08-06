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

#include "p101_identity/p101_grp.h"
#include "p101_identity/p101_pwd.h"
#include "p101_identity/p101_unistd.h"
#include "p101_identity/p101_utmpx.h"
#include <p101_env/wrapper.h>

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
