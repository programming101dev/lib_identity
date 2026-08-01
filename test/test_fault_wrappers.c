#include <errno.h>
#include <p101_env/env.h>
#include <p101_error/error.h>
#include <p101_identity/identity.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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

struct fault_state
{
    int checks;
    int errnum;
};

static int fail_next_call(const struct p101_env *env, const char *call_name, void *user_data)
{
    struct fault_state *state;

    (void)env;
    (void)call_name;
    state = user_data;
    state->checks++;
    return state->errnum;
}

/* P101_TEST_CASE(p101_crypt) */
static void test_p101_crypt(struct p101_env *env, struct p101_error *err)
{
#ifdef __linux__
    static const int errors[] = {EINVAL, ENOSYS, EPERM};
#elif defined(__APPLE__)
    static const int errors[] = {EIO};
#elif defined(__FreeBSD__)
    static const int errors[] = {EIO};
#else
    static const int errors[] = {ENOSYS};
#endif

    for(size_t index = 0U; index < sizeof(errors) / sizeof(errors[0]); index++)
    {
        struct fault_state state = {0, errors[index]};

        p101_env_set_fault_injector(env, fail_next_call, &state);
        char *result = p101_crypt(env, err, NULL, NULL);
        (void)result;
        EXPECT(state.checks == 1);
        EXPECT(p101_error_is_errno(err, state.errnum));
        p101_error_reset(err);
    }
    p101_env_set_fault_injector(env, NULL, NULL);
}

/* P101_TEST_CASE(p101_getgrgid_r) */
static void test_p101_getgrgid_r(struct p101_env *env, struct p101_error *err)
{
#ifdef __linux__
    static const int errors[] = {EBADF, EINTR, EIO, EMFILE, ENFILE, ENOENT, ENOMEM, EPERM, ERANGE, ESRCH};
#elif defined(__APPLE__)
    static const int errors[] = {EIO};
#elif defined(__FreeBSD__)
    static const int errors[] = {EIO};
#else
    static const int errors[] = {EINTR, EIO, EMFILE, ENFILE, ERANGE};
#endif

    for(size_t index = 0U; index < sizeof(errors) / sizeof(errors[0]); index++)
    {
        struct fault_state state = {0, errors[index]};

        p101_env_set_fault_injector(env, fail_next_call, &state);
        int result = p101_getgrgid_r(env, err, 0, NULL, NULL, 0, NULL);
        (void)result;
        EXPECT(state.checks == 1);
        EXPECT(p101_error_is_errno(err, state.errnum));
        p101_error_reset(err);
    }
    p101_env_set_fault_injector(env, NULL, NULL);
}

/* P101_TEST_CASE(p101_getgrnam_r) */
static void test_p101_getgrnam_r(struct p101_env *env, struct p101_error *err)
{
#ifdef __linux__
    static const int errors[] = {EBADF, EINTR, EIO, EMFILE, ENFILE, ENOENT, ENOMEM, EPERM, ERANGE, ESRCH};
#elif defined(__APPLE__)
    static const int errors[] = {EIO};
#elif defined(__FreeBSD__)
    static const int errors[] = {EIO};
#else
    static const int errors[] = {EINTR, EIO, EMFILE, ENFILE, ERANGE};
#endif

    for(size_t index = 0U; index < sizeof(errors) / sizeof(errors[0]); index++)
    {
        struct fault_state state = {0, errors[index]};

        p101_env_set_fault_injector(env, fail_next_call, &state);
        int result = p101_getgrnam_r(env, err, NULL, NULL, NULL, 0, NULL);
        (void)result;
        EXPECT(state.checks == 1);
        EXPECT(p101_error_is_errno(err, state.errnum));
        p101_error_reset(err);
    }
    p101_env_set_fault_injector(env, NULL, NULL);
}

/* P101_TEST_CASE(p101_getgroups) */
static void test_p101_getgroups(struct p101_env *env, struct p101_error *err)
{
#ifdef __linux__
    static const int errors[] = {EFAULT, EINVAL};
#elif defined(__APPLE__)
    static const int errors[] = {EFAULT, EINVAL};
#elif defined(__FreeBSD__)
    static const int errors[] = {EFAULT, EINVAL};
#else
    static const int errors[] = {EINVAL};
#endif

    for(size_t index = 0U; index < sizeof(errors) / sizeof(errors[0]); index++)
    {
        struct fault_state state = {0, errors[index]};

        p101_env_set_fault_injector(env, fail_next_call, &state);
        int result = p101_getgroups(env, err, 0, NULL);
        (void)result;
        EXPECT(state.checks == 1);
        EXPECT(p101_error_is_errno(err, state.errnum));
        p101_error_reset(err);
    }
    p101_env_set_fault_injector(env, NULL, NULL);
}

/* P101_TEST_CASE(p101_getlogin_r) */
static void test_p101_getlogin_r(struct p101_env *env, struct p101_error *err)
{
#ifdef __linux__
    static const int errors[] = {EMFILE, ENFILE, ENOENT, ENOMEM, ENOTTY, ENXIO, ERANGE};
#elif defined(__APPLE__)
    static const int errors[] = {EMFILE, ENFILE, ENOTTY, ENXIO, ERANGE};
#elif defined(__FreeBSD__)
    static const int errors[] = {EFAULT, EINVAL, EPERM, ERANGE};
#else
    static const int errors[] = {EMFILE, ENFILE, ENOTTY, ENXIO, ERANGE};
#endif

    for(size_t index = 0U; index < sizeof(errors) / sizeof(errors[0]); index++)
    {
        struct fault_state state = {0, errors[index]};

        p101_env_set_fault_injector(env, fail_next_call, &state);
        int result = p101_getlogin_r(env, err, NULL, 0);
        (void)result;
        EXPECT(state.checks == 1);
        EXPECT(p101_error_is_errno(err, state.errnum));
        p101_error_reset(err);
    }
    p101_env_set_fault_injector(env, NULL, NULL);
}

/* P101_TEST_CASE(p101_getpwnam_r) */
static void test_p101_getpwnam_r(struct p101_env *env, struct p101_error *err)
{
#ifdef __linux__
    static const int errors[] = {EBADF, EINTR, EIO, EMFILE, ENFILE, ENOENT, ENOMEM, EPERM, ERANGE, ESRCH};
#elif defined(__APPLE__)
    static const int errors[] = {ERANGE};
#elif defined(__FreeBSD__)
    static const int errors[] = {ERANGE};
#else
    static const int errors[] = {EINTR, EIO, EMFILE, ENFILE, ERANGE};
#endif

    for(size_t index = 0U; index < sizeof(errors) / sizeof(errors[0]); index++)
    {
        struct fault_state state = {0, errors[index]};

        p101_env_set_fault_injector(env, fail_next_call, &state);
        int result = p101_getpwnam_r(env, err, NULL, NULL, NULL, 0, NULL);
        (void)result;
        EXPECT(state.checks == 1);
        EXPECT(p101_error_is_errno(err, state.errnum));
        p101_error_reset(err);
    }
    p101_env_set_fault_injector(env, NULL, NULL);
}

/* P101_TEST_CASE(p101_getpwuid_r) */
static void test_p101_getpwuid_r(struct p101_env *env, struct p101_error *err)
{
#ifdef __linux__
    static const int errors[] = {EBADF, EINTR, EIO, EMFILE, ENFILE, ENOENT, ENOMEM, EPERM, ERANGE, ESRCH};
#elif defined(__APPLE__)
    static const int errors[] = {ERANGE};
#elif defined(__FreeBSD__)
    static const int errors[] = {ERANGE};
#else
    static const int errors[] = {EINTR, EIO, EMFILE, ENFILE, ERANGE};
#endif

    for(size_t index = 0U; index < sizeof(errors) / sizeof(errors[0]); index++)
    {
        struct fault_state state = {0, errors[index]};

        p101_env_set_fault_injector(env, fail_next_call, &state);
        int result = p101_getpwuid_r(env, err, 0, NULL, NULL, 0, NULL);
        (void)result;
        EXPECT(state.checks == 1);
        EXPECT(p101_error_is_errno(err, state.errnum));
        p101_error_reset(err);
    }
    p101_env_set_fault_injector(env, NULL, NULL);
}

/* P101_TEST_CASE(p101_pututxline) */
static void test_p101_pututxline(struct p101_env *env, struct p101_error *err)
{
#ifdef __linux__
    static const int errors[] = {EIO};
#elif defined(__APPLE__)
    static const int errors[] = {EINVAL, EPERM};
#elif defined(__FreeBSD__)
    static const int errors[] = {EINVAL, ESRCH};
#else
    static const int errors[] = {EPERM};
#endif

    for(size_t index = 0U; index < sizeof(errors) / sizeof(errors[0]); index++)
    {
        struct fault_state state = {0, errors[index]};

        p101_env_set_fault_injector(env, fail_next_call, &state);
        struct utmpx *result = p101_pututxline(env, err, NULL);
        (void)result;
        EXPECT(state.checks == 1);
        EXPECT(p101_error_is_errno(err, state.errnum));
        p101_error_reset(err);
    }
    p101_env_set_fault_injector(env, NULL, NULL);
}

/* P101_TEST_CASE(p101_setegid) */
static void test_p101_setegid(struct p101_env *env, struct p101_error *err)
{
#ifdef __linux__
    static const int errors[] = {EINVAL};
#elif defined(__APPLE__)
    static const int errors[] = {EINVAL, EPERM};
#elif defined(__FreeBSD__)
    static const int errors[] = {EPERM};
#else
    static const int errors[] = {EINVAL, EPERM};
#endif

    for(size_t index = 0U; index < sizeof(errors) / sizeof(errors[0]); index++)
    {
        struct fault_state state = {0, errors[index]};

        p101_env_set_fault_injector(env, fail_next_call, &state);
        int result = p101_setegid(env, err, 0);
        (void)result;
        EXPECT(state.checks == 1);
        EXPECT(p101_error_is_errno(err, state.errnum));
        p101_error_reset(err);
    }
    p101_env_set_fault_injector(env, NULL, NULL);
}

/* P101_TEST_CASE(p101_seteuid) */
static void test_p101_seteuid(struct p101_env *env, struct p101_error *err)
{
#ifdef __linux__
    static const int errors[] = {EINVAL, EPERM};
#elif defined(__APPLE__)
    static const int errors[] = {EINVAL, EPERM};
#elif defined(__FreeBSD__)
    static const int errors[] = {EPERM};
#else
    static const int errors[] = {EINVAL, EPERM};
#endif

    for(size_t index = 0U; index < sizeof(errors) / sizeof(errors[0]); index++)
    {
        struct fault_state state = {0, errors[index]};

        p101_env_set_fault_injector(env, fail_next_call, &state);
        int result = p101_seteuid(env, err, 0);
        (void)result;
        EXPECT(state.checks == 1);
        EXPECT(p101_error_is_errno(err, state.errnum));
        p101_error_reset(err);
    }
    p101_env_set_fault_injector(env, NULL, NULL);
}

/* P101_TEST_CASE(p101_setgid) */
static void test_p101_setgid(struct p101_env *env, struct p101_error *err)
{
#ifdef __linux__
    static const int errors[] = {EINVAL, EPERM};
#elif defined(__APPLE__)
    static const int errors[] = {EINVAL, EPERM};
#elif defined(__FreeBSD__)
    static const int errors[] = {EPERM};
#else
    static const int errors[] = {EINVAL, EPERM};
#endif

    for(size_t index = 0U; index < sizeof(errors) / sizeof(errors[0]); index++)
    {
        struct fault_state state = {0, errors[index]};

        p101_env_set_fault_injector(env, fail_next_call, &state);
        int result = p101_setgid(env, err, 0);
        (void)result;
        EXPECT(state.checks == 1);
        EXPECT(p101_error_is_errno(err, state.errnum));
        p101_error_reset(err);
    }
    p101_env_set_fault_injector(env, NULL, NULL);
}

/* P101_TEST_CASE(p101_setregid) */
static void test_p101_setregid(struct p101_env *env, struct p101_error *err)
{
#ifdef __linux__
    static const int errors[] = {EAGAIN, EINVAL, EPERM};
#elif defined(__APPLE__)
    static const int errors[] = {EPERM};
#elif defined(__FreeBSD__)
    static const int errors[] = {EPERM};
#else
    static const int errors[] = {EINVAL, EPERM};
#endif

    for(size_t index = 0U; index < sizeof(errors) / sizeof(errors[0]); index++)
    {
        struct fault_state state = {0, errors[index]};

        p101_env_set_fault_injector(env, fail_next_call, &state);
        int result = p101_setregid(env, err, 0, 0);
        (void)result;
        EXPECT(state.checks == 1);
        EXPECT(p101_error_is_errno(err, state.errnum));
        p101_error_reset(err);
    }
    p101_env_set_fault_injector(env, NULL, NULL);
}

/* P101_TEST_CASE(p101_setreuid) */
static void test_p101_setreuid(struct p101_env *env, struct p101_error *err)
{
#ifdef __linux__
    static const int errors[] = {EAGAIN, EINVAL, EPERM};
#elif defined(__APPLE__)
    static const int errors[] = {EPERM};
#elif defined(__FreeBSD__)
    static const int errors[] = {EPERM};
#else
    static const int errors[] = {EINVAL, EPERM};
#endif

    for(size_t index = 0U; index < sizeof(errors) / sizeof(errors[0]); index++)
    {
        struct fault_state state = {0, errors[index]};

        p101_env_set_fault_injector(env, fail_next_call, &state);
        int result = p101_setreuid(env, err, 0, 0);
        (void)result;
        EXPECT(state.checks == 1);
        EXPECT(p101_error_is_errno(err, state.errnum));
        p101_error_reset(err);
    }
    p101_env_set_fault_injector(env, NULL, NULL);
}

/* P101_TEST_CASE(p101_setuid) */
static void test_p101_setuid(struct p101_env *env, struct p101_error *err)
{
#ifdef __linux__
    static const int errors[] = {EAGAIN, EINVAL, EPERM};
#elif defined(__APPLE__)
    static const int errors[] = {EINVAL, EPERM};
#elif defined(__FreeBSD__)
    static const int errors[] = {EPERM};
#else
    static const int errors[] = {EINVAL, EPERM};
#endif

    for(size_t index = 0U; index < sizeof(errors) / sizeof(errors[0]); index++)
    {
        struct fault_state state = {0, errors[index]};

        p101_env_set_fault_injector(env, fail_next_call, &state);
        int result = p101_setuid(env, err, 0);
        (void)result;
        EXPECT(state.checks == 1);
        EXPECT(p101_error_is_errno(err, state.errnum));
        p101_error_reset(err);
    }
    p101_env_set_fault_injector(env, NULL, NULL);
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
    test_p101_crypt(env, err);
    test_p101_getgrgid_r(env, err);
    test_p101_getgrnam_r(env, err);
    test_p101_getgroups(env, err);
    test_p101_getlogin_r(env, err);
    test_p101_getpwnam_r(env, err);
    test_p101_getpwuid_r(env, err);
    test_p101_pututxline(env, err);
    test_p101_setegid(env, err);
    test_p101_seteuid(env, err);
    test_p101_setgid(env, err);
    test_p101_setregid(env, err);
    test_p101_setreuid(env, err);
    test_p101_setuid(env, err);
    p101_env_destroy(env);
    p101_error_destroy(err);
    return failures == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
