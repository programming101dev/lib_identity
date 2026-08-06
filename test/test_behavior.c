#include <p101_env/env.h>
#include <p101_error/error.h>
#include <p101_identity/p101_grp.h>
#include <p101_identity/p101_pwd.h>
#include <p101_identity/p101_unistd.h>
#include <p101_identity/p101_utmpx.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <utmpx.h>

static int failures;

#define EXPECT(condition)                                                                                                                                                                                                                                          \
    do                                                                                                                                                                                                                                                             \
    {                                                                                                                                                                                                                                                              \
        if(!(condition))                                                                                                                                                                                                                                           \
        {                                                                                                                                                                                                                                                          \
            fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #condition);                                                                                                                                                                                   \
            failures++;                                                                                                                                                                                                                                            \
        }                                                                                                                                                                                                                                                          \
    } while(0)

static void test_identity_getters(const struct p101_env *env)
{
    /* P101_TEST_CASE(p101_getuid) */
    EXPECT(p101_getuid(env) == getuid());
    /* P101_TEST_CASE(p101_geteuid) */
    EXPECT(p101_geteuid(env) == geteuid());
    /* P101_TEST_CASE(p101_getgid) */
    EXPECT(p101_getgid(env) == getgid());
    /* P101_TEST_CASE(p101_getegid) */
    EXPECT(p101_getegid(env) == getegid());
}

static void test_user_shell_database(const struct p101_env *env)
{
    char *shell;

    /* P101_TEST_CASE(p101_setusershell) */
    p101_setusershell(env);
    /* P101_TEST_CASE(p101_getusershell) */
    shell = p101_getusershell(env);
    (void)shell;
    /* P101_TEST_CASE(p101_endusershell) */
    p101_endusershell(env);
}

static void test_utmpx_database(const struct p101_env *env)
{
    struct utmpx  query = {0};
    struct utmpx *entry;

    /* P101_TEST_CASE(p101_setutxent) */
    p101_setutxent(env);
    /* P101_TEST_CASE(p101_getutxent) */
    entry = p101_getutxent(env);
    (void)entry;

    /* P101_TEST_CASE(p101_getutxid) */
    entry = p101_getutxid(env, &query);
    (void)entry;
    /* P101_TEST_CASE(p101_getutxline) */
    entry = p101_getutxline(env, &query);
    (void)entry;
    /* P101_TEST_CASE(p101_endutxent) */
    p101_endutxent(env);
}

int main(void)
{
    struct p101_error *err;
    struct p101_env   *env;

    err = p101_error_create(false);
    if(err == NULL)
    {
        return EXIT_FAILURE;
    }
    env = p101_env_create(err, NULL);
    if(env == NULL)
    {
        p101_error_destroy(err);
        return EXIT_FAILURE;
    }
    test_identity_getters(env);
    test_user_shell_database(env);
    test_utmpx_database(env);
    p101_env_destroy(env);
    p101_error_destroy(err);
    return failures == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
