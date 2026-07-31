#include "p101_identity/identity.h"
#include <p101_env/wrapper.h>
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
    P101_WRAPPER_FAULT_RETURN(env, err, NULL);
    errno   = 0;
    ret_val = pututxline(utmpx);

    if(ret_val == NULL)
    {
        P101_ERROR_RAISE_ERRNO(err, utmpx_error_code());
    }

    P101_TRACE_EXIT(env);
    return ret_val;
}

void p101_setutxent(const struct p101_env *env)
{
    P101_TRACE(env);
    errno = 0;
    setutxent();
    P101_TRACE_EXIT(env);
}
