#include "p101_identity/identity.h"
#include <p101_env/wrapper.h>
#ifdef __linux__
    #include <crypt.h>
#endif
#include <unistd.h>

char *p101_crypt(const struct p101_env *env, struct p101_error *err, const char *key, const char *salt)
{
    char *ret_val;

    P101_TRACE(env);
    P101_WRAPPER_FAULT_RETURN(env, err, NULL);
    errno   = 0;
    ret_val = crypt(key, salt);    // cppcheck-suppress cryptCalled

    if(ret_val == NULL)
    {
        P101_ERROR_RAISE_ERRNO(err, (errno == 0) ? EIO : errno);
    }

    P101_TRACE_EXIT(env);
    return ret_val;
}

int p101_setregid(const struct p101_env *env, struct p101_error *err, gid_t rgid, gid_t egid)
{
    int ret_val;

    P101_TRACE(env);
    P101_WRAPPER_FAULT_RETURN(env, err, -1);
    errno   = 0;
    ret_val = setregid(rgid, egid);

    if(ret_val == -1)
    {
        P101_ERROR_RAISE_ERRNO(err, errno);
    }

    P101_TRACE_EXIT(env);
    return ret_val;
}

int p101_setreuid(const struct p101_env *env, struct p101_error *err, uid_t ruid, uid_t euid)
{
    int ret_val;

    P101_TRACE(env);
    P101_WRAPPER_FAULT_RETURN(env, err, -1);
    errno   = 0;
    ret_val = setreuid(ruid, euid);

    if(ret_val == -1)
    {
        P101_ERROR_RAISE_ERRNO(err, errno);
    }

    P101_TRACE_EXIT(env);
    return ret_val;
}
